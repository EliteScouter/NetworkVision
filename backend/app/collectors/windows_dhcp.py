"""Windows Server DHCP + DNS collector (read-only, over WinRM / PowerShell Remoting).

One PowerShell script per refresh reads scopes, scope statistics, options, exclusions,
reservations, leases, failover relationships and server settings from the DhcpServer
module and returns JSON. Leases feed the normal DHCP insights (conflicts, new devices...);
the rest powers the Windows-specific checks in services/windhcp.py (failover health,
configuration drift between partners, scope exhaustion, BAD_ADDRESS, static IPs in pools).

DNS: the server is also queried directly over DNS (collectors/dns_probe.py: AD locator records,
external resolution, lease <-> A/PTR consistency). Zones, forwarders and scavenging are read
when the account is allowed to; the DNS Server event log needs **Event Log Readers**.

Least privilege: a plain domain account in the **DHCP Users** group (read-only DHCP) and
**Remote Management Users** (WinRM) on each server. Never a domain admin, and not DnsAdmins
(that group can take over the domain).
"""

from __future__ import annotations

import asyncio
import copy
import json
import logging
import time
from typing import Any

from ..services.clients import from_lease
from . import dns_probe
from .base import Collector, CollectorError, FieldSpec, Section, Snapshot, norm_mac

ACTIVE_STATES = {"active", "activereservation"}

# pypsrp logs the whole script at INFO on every run; spnego can log auth details at DEBUG.
for _name in ("pypsrp", "spnego"):
    logging.getLogger(_name).setLevel(logging.WARNING)

# Kept PowerShell 5.1 compatible (Windows Server 2016+). __MAX__ is replaced with the lease cap.
SCRIPT = r"""
$ErrorActionPreference = 'Stop'
Import-Module DhcpServer
function U($d) { if ($d) { ([DateTimeOffset]$d).ToUnixTimeSeconds() } else { $null } }
function Opts($list) {
  @($list | ForEach-Object { [ordered]@{ id = [int]$_.OptionId; name = "$($_.Name)"; value = @($_.Value | ForEach-Object { "$_" }) } })
}
# Optional reads never abort the run: a denied cmdlet becomes a warning and the rest still flows.
$W = New-Object System.Collections.Generic.List[string]
function T([string]$what, [scriptblock]$sb) {
  try { & $sb } catch { $W.Add("${what}: $($_.Exception.Message)"); $null }
}
$srv = T 'Get-DhcpServerSetting' { Get-DhcpServerSetting }
$fqdn = $env:COMPUTERNAME
try { $fqdn = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName } catch { }
$out = [ordered]@{
  server = $env:COMPUTERNAME; fqdn = $fqdn
  authorized = $(if ($srv) { [bool]$srv.IsAuthorized } else { $null })
  conflict_attempts = $(if ($srv) { [int]$srv.ConflictDetectionAttempts } else { $null })
  server_options = Opts (T 'Get-DhcpServerv4OptionValue' { Get-DhcpServerv4OptionValue })
  failover = @(T 'Get-DhcpServerv4Failover' { Get-DhcpServerv4Failover } | ForEach-Object { [ordered]@{
    name = "$($_.Name)"; partner = "$($_.PartnerServer)"; mode = "$($_.Mode)"; state = "$($_.State)"
    role = "$($_.ServerRole)"; lb = [int]$_.LoadBalancePercent; reserve = [int]$_.ReservePercent
    scopes = @($_.ScopeId | ForEach-Object { "$_" }) } })
  truncated = $false
}
$scopes = New-Object System.Collections.Generic.List[object]
$leases = New-Object System.Collections.Generic.List[object]
$max = __MAX__
foreach ($s in Get-DhcpServerv4Scope) {
  $id = $s.ScopeId
  $st = T "Get-DhcpServerv4ScopeStatistics $id" { Get-DhcpServerv4ScopeStatistics -ScopeId $id }
  $scopes.Add([ordered]@{
    id = "$id"; name = "$($s.Name)"; mask = "$($s.SubnetMask)"; start = "$($s.StartRange)"; end = "$($s.EndRange)"
    state = "$($s.State)"; lease_s = [int64]$s.LeaseDuration.TotalSeconds
    in_use = [int]$st.InUse; free = [int]$st.Free; pct = [double]$st.PercentageInUse; reserved = [int]$st.Reserved
    options = Opts (T "Get-DhcpServerv4OptionValue $id" { Get-DhcpServerv4OptionValue -ScopeId $id })
    exclusions = @(T "Get-DhcpServerv4ExclusionRange $id" { Get-DhcpServerv4ExclusionRange -ScopeId $id } |
      ForEach-Object { "$($_.StartRange)-$($_.EndRange)" })
    reservations = @(T "Get-DhcpServerv4Reservation $id" { Get-DhcpServerv4Reservation -ScopeId $id } | ForEach-Object {
      [ordered]@{ ip = "$($_.IPAddress)"; mac = "$($_.ClientId)"; name = "$($_.Name)"; type = "$($_.Type)" } })
  })
  foreach ($l in @(T "Get-DhcpServerv4Lease $id" { Get-DhcpServerv4Lease -ScopeId $id })) {
    if ($null -eq $l) { continue }
    if ($leases.Count -ge $max) { $out.truncated = $true; break }
    $leases.Add([ordered]@{ ip = "$($l.IPAddress)"; mac = "$($l.ClientId)"; host = "$($l.HostName)"
      state = "$($l.AddressState)"; scope = "$id"; expires = (U $l.LeaseExpiryTime) })
  }
}
$out.scopes = $scopes.ToArray()
$out.leases = $leases.ToArray()
$dns = [ordered]@{ available = $false }
if (Get-Module -ListAvailable -Name DnsServer) {
  $dns.available = $true
  try {
    $dns.zones = @(Get-DnsServerZone | Where-Object { -not $_.IsAutoCreated -and $_.ZoneName -ne 'TrustAnchors' } | ForEach-Object {
      [ordered]@{ name = "$($_.ZoneName)"; type = "$($_.ZoneType)"; ad = [bool]$_.IsDsIntegrated
        reverse = [bool]$_.IsReverseLookupZone; dynamic = "$($_.DynamicUpdate)"; paused = [bool]$_.IsPaused } })
    $dns.forwarders = @((Get-DnsServerForwarder).IPAddress | ForEach-Object { "$_" })
    $dns.scavenging = [bool](Get-DnsServerScavenging).ScavengingState
  } catch { $dns.config_error = "$($_.Exception.Message)" }
}
try {
  $since = (Get-Date).AddHours(-24)
  $dns.events = @(Get-WinEvent -FilterHashtable @{ LogName = 'DNS Server'; Level = 2, 3; StartTime = $since } -MaxEvents 25 |
    ForEach-Object { [ordered]@{ id = [int]$_.Id; level = [int]$_.Level; ts = (U $_.TimeCreated); msg = "$((($_.Message) -split "`r?`n")[0])" } })
} catch {
  if ("$($_.FullyQualifiedErrorId)" -like 'NoMatchingEventsFound*') { $dns.events = @() } else { $dns.events_error = "$($_.Exception.Message)" }
}
$out.dns = $dns
$out.warnings = $W.ToArray()
$out | ConvertTo-Json -Depth 6 -Compress
"""


def _list(v: Any) -> list[Any]:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _opts(raw: Any) -> list[dict[str, Any]]:
    out = []
    for o in _list(raw):
        if isinstance(o, dict) and o.get("id") is not None:
            out.append({"id": int(o["id"]), "name": str(o.get("name") or ""), "value": [str(x) for x in _list(o.get("value"))]})
    return sorted(out, key=lambda o: o["id"])


def is_placeholder(mac: str) -> bool:
    """Made-up client IDs (00:00:00:00:00:01...) used to hold an address for a statically configured device."""
    return not mac or mac.startswith("00:00:00:00:00") or mac in ("ff:ff:ff:ff:ff:ff",) or len(set(mac.replace(":", ""))) == 1


def is_bad_address(lease: dict[str, Any]) -> bool:
    return str(lease.get("host") or "").upper() == "BAD_ADDRESS" or "declined" in str(lease.get("state") or "").lower()


def normalize(raw: dict[str, Any]) -> dict[str, Any]:
    """Tidy the PowerShell JSON (single items vs lists, MAC format, option values)."""
    scopes = []
    for s in _list(raw.get("scopes")):
        scopes.append({
            "id": str(s.get("id") or ""), "name": str(s.get("name") or ""), "mask": str(s.get("mask") or ""),
            "start": str(s.get("start") or ""), "end": str(s.get("end") or ""), "state": str(s.get("state") or ""),
            "lease_s": int(s.get("lease_s") or 0), "in_use": int(s.get("in_use") or 0), "free": int(s.get("free") or 0),
            "pct": round(float(s.get("pct") or 0), 1), "reserved": int(s.get("reserved") or 0),
            "options": _opts(s.get("options")),
            "exclusions": sorted(str(x) for x in _list(s.get("exclusions"))),
            "reservations": sorted(({"ip": str(r.get("ip") or ""), "mac": norm_mac(str(r.get("mac") or "")),
                                     "name": str(r.get("name") or ""), "type": str(r.get("type") or "")}
                                    for r in _list(s.get("reservations")) if isinstance(r, dict)), key=lambda r: r["ip"]),
        })
    leases = [{"ip": str(le.get("ip") or ""), "mac": norm_mac(str(le.get("mac") or "")), "host": str(le.get("host") or ""),
               "state": str(le.get("state") or ""), "scope": str(le.get("scope") or ""), "expires": le.get("expires")}
              for le in _list(raw.get("leases")) if isinstance(le, dict)]
    failover = [{"name": str(f.get("name") or ""), "partner": str(f.get("partner") or ""), "mode": str(f.get("mode") or ""),
                 "state": str(f.get("state") or ""), "role": str(f.get("role") or ""), "lb": f.get("lb"),
                 "reserve": f.get("reserve"), "scopes": sorted(str(x) for x in _list(f.get("scopes")))}
                for f in _list(raw.get("failover")) if isinstance(f, dict) and f.get("name")]
    d = raw.get("dns") if isinstance(raw.get("dns"), dict) else {}
    dns = {
        "available": bool(d.get("available")),
        "zones": [{"name": str(z.get("name") or ""), "type": str(z.get("type") or ""), "ad": bool(z.get("ad")),
                   "reverse": bool(z.get("reverse")), "dynamic": str(z.get("dynamic") or ""), "paused": bool(z.get("paused"))}
                  for z in _list(d.get("zones")) if isinstance(z, dict)] if "zones" in d else None,
        "forwarders": [str(x) for x in _list(d.get("forwarders"))] if "forwarders" in d else None,
        "scavenging": d.get("scavenging"),
        "config_error": str(d["config_error"])[:300] if d.get("config_error") else None,
        "events": [{"id": int(e.get("id") or 0), "level": int(e.get("level") or 0), "ts": e.get("ts"),
                    "msg": str(e.get("msg") or "")[:300]} for e in _list(d.get("events")) if isinstance(e, dict)]
                  if "events" in d else None,
        "events_error": str(d["events_error"])[:300] if d.get("events_error") else None,
    }
    return {
        "dns": dns,
        "server": str(raw.get("server") or ""), "fqdn": str(raw.get("fqdn") or raw.get("server") or ""),
        "authorized": raw.get("authorized"), "conflict_attempts": raw.get("conflict_attempts"),
        "server_options": _opts(raw.get("server_options")), "failover": failover, "scopes": scopes,
        "leases": leases, "truncated": bool(raw.get("truncated")),
        "warnings": [str(w)[:300] for w in _list(raw.get("warnings"))][:20],
    }


def build_snapshot(data: dict[str, Any]) -> Snapshot:
    leases = data["leases"]
    good = [le for le in leases if not is_bad_address(le)]
    active = [le for le in good if le["state"].lower() in ACTIVE_STATES]
    snap = Snapshot()
    snap.metrics["clients"] = len(active)
    snap.facts.update({"hostname": data["fqdn"], "dhcp_authorized": data["authorized"]})
    # Windows lists every reservation as "ActiveReservation" whether or not the device is online, so a
    # reservation is not evidence that the address is in use (an old VM's MAC would look like a conflict).
    snap.clients = [from_lease(le["mac"], le["ip"], le["host"], _lease_state(le["state"]), f"scope {le['scope']}", le["expires"])
                    for le in good if le["mac"] and not is_placeholder(le["mac"])]
    by_scope_fo = {sc: f["name"] for f in data["failover"] for sc in f["scopes"]}
    snap.dhcp_server = {
        **{k: data[k] for k in ("server", "fqdn", "authorized", "conflict_attempts", "server_options", "failover", "truncated", "dns", "warnings")},
        "scopes": [{**s, "failover": by_scope_fo.get(s["id"], "")} for s in data["scopes"]],
        "bad": [{"ip": le["ip"], "scope": le["scope"]} for le in leases if is_bad_address(le)],
        "pairs": [[le["mac"], le["ip"]] for le in active if le["mac"]],
        "lease_count": len(leases),
    }
    snap.sections = [
        Section(id="scopes", title="DHCP scopes", columns=["Scope", "Name", "Range", "State", "In use", "Free", "Used %", "Failover"],
                rows=[[s["id"], s["name"], f"{s['start']} – {s['end']}", s["state"], s["in_use"], s["free"], s["pct"],
                       by_scope_fo.get(s["id"], "—")] for s in data["scopes"]]),
        Section(id="failover", title="Failover relationships", columns=["Name", "Partner", "Mode", "State", "Role", "Scopes"],
                rows=[[f["name"], f["partner"], f["mode"], f["state"], f["role"], ", ".join(f["scopes"])] for f in data["failover"]]),
        Section(id="reservations", title="Reservations", columns=["IP", "MAC", "Name", "Scope"],
                rows=[[r["ip"], r["mac"], r["name"], s["id"]] for s in data["scopes"] for r in s["reservations"]][:1000]),
        Section(id="dhcp", title="DHCP leases", columns=["IP", "MAC", "Hostname", "Scope", "State"],
                rows=[[le["ip"], le["mac"], le["host"], le["scope"], le["state"]] for le in leases[:500]]),
    ]
    return snap


def _lease_state(state: str) -> str:
    s = state.lower()
    return "active" if s == "active" else "reserved" if s == "activereservation" else s


class WindowsDhcpCollector(Collector):
    kind = "windows_dhcp"
    label = "Windows Server DHCP & DNS (WinRM)"
    vendor = "Microsoft"
    description = (
        "Scopes, leases, reservations and failover health from Windows Server DHCP, plus DNS health, over WinRM (read-only). "
        "Add each failover partner (e.g. DC01 and DC02) to compare their configuration and catch drift."
    )
    default_role = "server"
    fields = [
        FieldSpec(key="scheme", label="Transport", type="select", options=["https", "http"], default="https",
                  help="WinRM over HTTPS (5986) is recommended; HTTP (5985) still encrypts with NTLM/Negotiate."),
        FieldSpec(key="port", label="Port", type="number", default=5986),
        FieldSpec(key="auth", label="Authentication", type="select", options=["ntlm", "negotiate", "basic"], default="ntlm",
                  help="Basic only over HTTPS. Kerberos isn't available inside the container."),
        FieldSpec(key="username", label="Username", type="text", required=True, placeholder="DOMAIN\\svc-networkvision",
                  help="Member of 'DHCP Users' and 'Remote Management Users' on this server - not an admin."),
        FieldSpec(key="password", label="Password", type="password", secret=True, required=True, placeholder="env:WINDHCP_PASSWORD"),
        FieldSpec(key="verify_tls", label="Verify TLS certificate", type="bool", default=False,
                  help="Turn on if the WinRM certificate comes from a CA the container trusts."),
        FieldSpec(key="dns_checks", label="Check DNS on this server", type="bool", default=True,
                  help="Query it directly: AD locator records, external resolution, and whether DHCP clients' A/PTR records match their leases."),
        FieldSpec(key="dns_domain", label="AD / DNS domain", type="text", placeholder="detected from the server name",
                  help="e.g. corp.example.com. Short lease hostnames are checked as <host>.<domain>."),
        FieldSpec(key="dns_test_name", label="External test name", type="text", default="cloudflare.com",
                  help="Resolved through this server to confirm forwarders / root hints work. Empty to skip."),
        FieldSpec(key="dns_lease_checks", label="Lease names to verify", type="number", default=300),
        FieldSpec(key="refresh", label="Refresh every (s)", type="number", default=60,
                  help="Full read of scopes and leases; between refreshes the last result is reused."),
        FieldSpec(key="max_leases", label="Max leases read", type="number", default=10000),
        FieldSpec(key="timeout", label="Timeout (s)", type="number", default=60),
    ]

    def __init__(self, host: str, config: dict[str, Any], secrets: dict[str, Any]) -> None:
        super().__init__(host, config, secrets)
        self._last: Snapshot | None = None
        self._last_at = 0.0

    def _run(self) -> dict[str, Any]:
        from pypsrp.client import Client  # imported lazily: only needed when this integration is used
        from pypsrp.exceptions import AuthenticationError, WinRMTransportError, WSManFaultError

        https = (self.opt("scheme") or "https") == "https"
        auth = str(self.opt("auth") or "ntlm")
        if auth == "basic" and not https:
            raise CollectorError("Basic authentication is only allowed over HTTPS")
        timeout = int(self.opt("timeout") or 60)
        max_leases = max(100, min(200000, int(self.opt("max_leases") or 10000)))
        try:
            client = Client(self.host, port=int(self.opt("port") or (5986 if https else 5985)), ssl=https, auth=auth,
                            username=str(self.opt("username") or ""), password=str(self.opt("password") or ""),
                            cert_validation=self.opt("verify_tls") in (True, "true", "1", 1),
                            connection_timeout=min(timeout, 30), read_timeout=timeout + 10, operation_timeout=timeout)
            output, streams, had_errors = client.execute_ps(SCRIPT.replace("__MAX__", str(max_leases)))
        except AuthenticationError as e:
            raise CollectorError(f"WinRM authentication failed - check the username/password ({type(e).__name__})") from e
        except WinRMTransportError as e:
            code = getattr(e, "code", None)
            hint = {401: "credentials rejected", 403: "account not in 'Remote Management Users'", 500: "WinRM server error"}
            raise CollectorError(f"WinRM HTTP {code}: {hint.get(code, 'transport error')}") from e
        except WSManFaultError as e:
            raise CollectorError(f"WinRM refused the request: {str(e)[:200]}") from e
        except OSError as e:  # requests' ConnectionError/Timeout derive from it
            raise CollectorError(f"Cannot reach WinRM on {self.host} ({type(e).__name__})") from e
        except Exception as e:  # noqa: BLE001 - surface anything else as a readable integration error
            if type(e).__module__.startswith(("requests", "urllib3")):
                raise CollectorError(f"Cannot reach WinRM on {self.host} ({type(e).__name__})") from e
            raise
        if had_errors and not output.strip():
            err = "; ".join(str(x) for x in streams.error)[:300] or "unknown PowerShell error"
            if "DhcpServer" in err and ("not loaded" in err or "not found" in err.lower()):
                err = "The DhcpServer PowerShell module isn't installed on this server (is it a DHCP server?)"
            elif "cim server" in err.lower() and "denied" in err.lower():
                err = (f"{err} - grant 'Enable Account' + 'Remote Enable' on the WMI namespace root/Microsoft/Windows/DHCP "
                       "to the 'DHCP Users' group on this server (WMI Control, wmimgmt.msc)")
            elif "denied" in err.lower():
                # Keep Windows' own text: it names the cmdlet/object that was refused.
                err = f"{err} (needs 'DHCP Users' + 'Remote Management Users'; sign-out/in or wait for a new token after adding)"
            raise CollectorError(err)
        try:
            return json.loads(output.strip().splitlines()[-1])
        except (ValueError, IndexError) as e:
            raise CollectorError("Unexpected output from the DHCP PowerShell script") from e

    async def collect(self) -> Snapshot:
        refresh = max(15, int(self.opt("refresh") or 60))
        if self._last is not None and time.monotonic() - self._last_at < refresh:
            return copy.deepcopy(self._last)
        raw = await asyncio.to_thread(self._run)
        data = normalize(raw)
        if self.opt("dns_checks") not in (False, "false", "0", 0):
            fqdn = data["fqdn"].lower()
            domain = str(self.opt("dns_domain") or (fqdn.split(".", 1)[1] if "." in fqdn else "")).strip(". ").lower()
            active = [le for le in data["leases"] if le["state"].lower() in ACTIVE_STATES and not is_bad_address(le)]
            try:
                data["dns"]["probe"] = await dns_probe.probe(
                    self.host, domain, fqdn, str(self.opt("dns_test_name") or "").strip(), active,
                    limit=max(0, min(5000, int(self.opt("dns_lease_checks") or 0))))
            except Exception as e:  # noqa: BLE001 - DNS checks must never break the DHCP data
                data["dns"]["probe"] = {"ok": False, "error": f"DNS check failed: {type(e).__name__}"}
        snap = build_snapshot(data)
        self._last, self._last_at = snap, time.monotonic()
        return copy.deepcopy(snap)

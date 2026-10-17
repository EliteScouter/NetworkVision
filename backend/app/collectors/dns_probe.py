"""Direct DNS checks against one (Windows / AD) DNS server - no credentials needed.

* Does the server answer for its AD domain (SOA) and how fast?
* Does it return the domain controller locator records (_ldap._tcp.dc._msdcs.<domain>)?
* Can it resolve an external name (forwarders / root hints working)?
* Do DHCP clients' DNS records match their leases (stale A records, PTR mismatches)?
"""

from __future__ import annotations

import asyncio
import socket
import time
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.resolver
import dns.reversename

NEGATIVE = (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer)


def _name(n: Any) -> str:
    return str(n).rstrip(".").lower()


async def server_ip(host: str) -> str:
    infos = await asyncio.get_running_loop().getaddrinfo(host, 53, family=socket.AF_INET, type=socket.SOCK_DGRAM)
    return infos[0][4][0]


def fqdn_for(host: str, domain: str) -> str:
    h = host.strip().rstrip(".").lower()
    return h if "." in h or not domain else f"{h}.{domain}"


async def probe(server: str, domain: str, own_fqdn: str, test_name: str, leases: list[dict[str, Any]],
                limit: int = 300, timeout: float = 2.0) -> dict[str, Any]:
    """``leases`` are this server's active leases: {"ip", "host"}. Never raises."""
    out: dict[str, Any] = {"server_ip": None, "domain": domain, "ok": False, "latency_ms": None, "error": None,
                           "dc_srv": [], "self_a": [], "external_ok": None, "external_error": None,
                           "checked": 0, "stale": [], "missing": 0, "ptr_mismatch": [], "ptr_missing": 0}
    try:
        ip = server if _is_ip(server) else await server_ip(server)
    except OSError as e:
        out["error"] = f"cannot resolve {server}: {type(e).__name__}"
        return out
    out["server_ip"] = ip
    r = dns.asyncresolver.Resolver(configure=False)
    r.nameservers, r.timeout, r.lifetime = [ip], timeout, timeout * 2

    async def q(name: str, rtype: str) -> list[Any] | None:
        """Answers, [] for NXDOMAIN/no data, None if the server failed to answer."""
        try:
            return list(await r.resolve(name, rtype, search=False, raise_on_no_answer=True))
        except NEGATIVE:
            return []
        except (dns.exception.DNSException, OSError):
            return None

    t0 = time.perf_counter()
    target = domain or own_fqdn
    soa = await q(target, "SOA") if target else None
    if soa is None:
        out["error"] = f"no answer for {target or 'its domain'}"
        return out
    out["ok"], out["latency_ms"] = True, round((time.perf_counter() - t0) * 1000, 1)
    if domain:
        srv = await q(f"_ldap._tcp.dc._msdcs.{domain}", "SRV") or []
        out["dc_srv"] = sorted({_name(x.target) for x in srv})
    if own_fqdn:
        out["self_a"] = sorted(x.address for x in (await q(own_fqdn, "A") or []))
    if test_name:
        ext = await q(test_name, "A")
        out["external_ok"] = bool(ext)
        if not ext:
            out["external_error"] = "no answer" if ext is None else "no records"

    # Lease <-> DNS consistency. A host can hold several leases (Wi-Fi + Ethernet): a record is only
    # stale when it points at none of that host's current lease addresses.
    by_host: dict[str, set[str]] = {}
    for le in leases:
        h = (le.get("host") or "").strip()
        if h and h.upper() != "BAD_ADDRESS" and le.get("ip"):
            name = fqdn_for(h, domain)
            # Only names this server is authoritative for: a laptop registered as "pc.othercorp.com" resolves
            # through forwarders to someone else's DNS, which says nothing about this server's records.
            if domain and not (name == domain or name.endswith("." + domain)):
                continue
            by_host.setdefault(name, set()).add(le["ip"])
    sem = asyncio.Semaphore(20)

    async def check(name: str, ips: set[str]) -> None:
        async with sem:
            a = await q(name, "A")
            if a is None:
                return
            out["checked"] += 1
            found = {x.address for x in a}
            if not found:
                out["missing"] += 1
            elif not found & ips:
                out["stale"].append({"host": name, "lease_ips": sorted(ips), "dns_ips": sorted(found)})
            for lease_ip in sorted(ips):
                ptr = await q(dns.reversename.from_address(lease_ip).to_text(), "PTR")
                if ptr is None:
                    continue
                names = {_name(x.target) for x in ptr}
                if not names:
                    out["ptr_missing"] += 1
                elif name not in names:
                    out["ptr_mismatch"].append({"ip": lease_ip, "host": name, "ptr": sorted(names)})

    await asyncio.gather(*(check(n, ips) for n, ips in sorted(by_host.items())[:limit]))
    out["stale"].sort(key=lambda x: x["host"])
    out["ptr_mismatch"].sort(key=lambda x: x["host"])
    return out


def _is_ip(s: str) -> bool:
    try:
        socket.inet_aton(s)
        return s.count(".") == 3
    except OSError:
        return False

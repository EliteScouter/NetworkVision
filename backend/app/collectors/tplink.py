"""TP-Link *Easy Smart* switch collector (TL-SG105E / TL-SG108E / TL-SG116E / TL-SG1016DE ...).

These switches have no SNMP and no API - only a small web UI. This collector logs
into that UI (read only) and parses the JavaScript variables it embeds.

Caveats (inherent to the hardware, documented for users):
* The web UI only allows one session per source IP; polling may sign you out of
  the UI if you browse it from the NetworkVision host.
* Counters are packets, not bytes, so throughput is shown as packets/s.
* Some newer firmware revisions changed the login form. If it fails, use the
  generic "Ping / TCP" monitor for basic up/down instead.

For TP-Link *managed* (JetStream/Omada) switches, use the SNMP collector.
"""

from __future__ import annotations

import re
from typing import Any

import httpx

from .base import CollectorError, FieldSpec, Interface, Section, Snapshot, norm_mac
from .http_base import HttpCollector

LINK_SPEED = {0: None, 1: None, 2: 10, 3: 10, 4: 100, 5: 100, 6: 1000}
LINK_TEXT = {0: "link down", 1: "auto", 2: "10 half", 3: "10 full", 4: "100 half", 5: "100 full", 6: "1000 full"}


def _js_var(html: str, name: str) -> dict[str, Any] | list[Any] | None:
    """Extract a JS object/array literal like `var all_info = {state:[1,0],...};`."""
    m = re.search(rf"var\s+{name}\s*=\s*(\{{.*?\}}|\[.*?\]);", html, re.S)
    if not m:
        return None
    body = m.group(1).strip()
    if body.startswith("["):
        return _js_list(body)
    out: dict[str, Any] = {}
    for key, val in re.findall(r"(\w+)\s*:\s*(\[[^\]]*\])", body, re.S):
        out[key] = _js_list(val)
    return out


def _js_list(text: str) -> list[Any]:
    items = []
    for raw in re.findall(r'"[^"]*"|\'[^\']*\'|[-\w.:]+', text[1:-1]):
        raw = raw.strip()
        if raw[:1] in "\"'":
            items.append(raw[1:-1])
        else:
            try:
                items.append(int(raw))
            except ValueError:
                items.append(raw)
    return items


class TplinkEasySmartCollector(HttpCollector):
    kind = "tplink_easysmart"
    label = "TP-Link Easy Smart switch (experimental)"
    vendor = "TP-Link"
    description = (
        "Port link state/speed and packet/error counters from TP-Link Easy Smart switches "
        "(TL-SG108E & friends) that have no SNMP. Read-only web UI scraping."
    )
    default_role = "switch"
    fields = [
        FieldSpec(key="scheme", label="Scheme", type="select", options=["http", "https"], default="http"),
        FieldSpec(key="port", label="Port", type="number", default=80),
        FieldSpec(key="username", label="Username", type="text", default="admin"),
        FieldSpec(key="password", label="Password", type="password", secret=True, required=True,
                  placeholder="env:TPLINK_PASSWORD"),
        FieldSpec(key="timeout", label="Timeout (s)", type="number", default=8),
    ]

    async def _login(self, c: httpx.AsyncClient) -> None:
        data = {"username": self.opt("username") or "admin", "password": self.opt("password") or "",
                "cpassword": "", "logon": "Login"}
        try:
            r = await c.post("/logon.cgi", data=data)
        except httpx.HTTPError as e:
            raise CollectorError(f"Cannot reach switch web UI: {e}") from e
        if r.status_code >= 400:
            raise CollectorError(f"Login failed (HTTP {r.status_code})")
        if "logonInfo" in r.text:
            info = _js_var(r.text, "logonInfo")
            if isinstance(info, list) and info and info[0] not in (0, "0"):
                raise CollectorError("Switch rejected the credentials (or another session is active)")

    async def _page(self, c: httpx.AsyncClient, path: str) -> str:
        r = await c.get(path)
        if r.status_code >= 400:
            raise CollectorError(f"HTTP {r.status_code} on {path}")
        return r.text

    async def collect(self) -> Snapshot:
        c = self.client()
        await self._login(c)
        try:
            sysinfo_html = await self._page(c, "/SystemInfoRpm.htm")
            if "logon" in sysinfo_html.lower() and "info_ds" not in sysinfo_html:
                raise CollectorError("Not logged in after login - unsupported firmware?")
            stats_html = await self._page(c, "/PortStatisticsRpm.htm")
            vlan_html = await self._page(c, "/Vlan8021QRpm.htm")
        finally:
            try:
                await c.get("/Logout.htm")  # free the single admin session slot
            except httpx.HTTPError:
                pass

        snap = Snapshot()
        info = _js_var(sysinfo_html, "info_ds") or {}

        def first(k: str) -> str:
            v = info.get(k) if isinstance(info, dict) else None
            return str(v[0]) if v else ""

        snap.facts = {"vendor": "TP-Link", "model": first("descriStr") or first("hardwareStr"),
                      "hardware": first("hardwareStr"), "version": first("firmwareStr"),
                      "mac": norm_mac(first("macStr")), "ip": first("ipStr")}

        stats = _js_var(stats_html, "all_info") or {}
        state = stats.get("state", []) if isinstance(stats, dict) else []
        link = stats.get("link_status", []) if isinstance(stats, dict) else []
        pkts = stats.get("pkts", []) if isinstance(stats, dict) else []
        m = re.search(r"max_port_num\s*=\s*(\d+)", stats_html)
        nports = int(m.group(1)) if m else len(link)
        for i in range(nports):
            ls = link[i] if i < len(link) else 0
            p = pkts[i * 4 : i * 4 + 4] if len(pkts) >= (i + 1) * 4 else [None] * 4
            tx_good, tx_bad, rx_good, rx_bad = (x if isinstance(x, int) else None for x in p)
            snap.interfaces.append(Interface(
                name=f"Port {i + 1}", index=i + 1,
                admin_up=(state[i] == 1) if i < len(state) else None,
                oper_up=ls not in (0, None), speed_mbps=LINK_SPEED.get(ls), media="copper",
                in_errors=rx_bad, out_errors=tx_bad,
                extra={"rx_pkts": rx_good, "tx_pkts": tx_good, "link": LINK_TEXT.get(ls, str(ls)), "counter": "packets"},
            ))

        vlans = _js_var(vlan_html, "qvlan_ds")
        if isinstance(vlans, dict) and vlans.get("vids"):
            names = vlans.get("names", [])
            snap.sections.append(Section(id="vlans", title="802.1Q VLANs", columns=["VLAN ID", "Name"], rows=[
                [vid, names[i] if i < len(names) else ""] for i, vid in enumerate(vlans["vids"])
            ]))
        return snap

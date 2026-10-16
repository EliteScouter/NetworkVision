"""Demo collector: a believable simulated homelab, used when NV_DEMO_MODE=true.

It produces exactly the same normalized snapshots as the real collectors (raw
counters, LLDP/uplink neighbors, gateways, logs, child devices), so the whole
pipeline - rates, alerts, topology, UI - is exercised end to end. Faults are
injected on a schedule so there is always something interesting on screen.
"""

from __future__ import annotations

import hashlib
import math
import random
import time
from dataclasses import dataclass, field
from typing import Any

from . import demo_firewall
from .base import ChildSnapshot, Collector, FieldSpec, Gateway, Interface, LogLine, Neighbor, Section, Snapshot

T0 = time.time()


def mac_for(*parts: Any) -> str:
    h = hashlib.sha1("|".join(map(str, parts)).encode()).hexdigest()
    return "02:" + ":".join(h[i : i + 2] for i in range(0, 10, 2))


def wave(period: float, phase: float = 0.0) -> float:
    """0..1 smooth daily-ish oscillation."""
    return 0.5 + 0.5 * math.sin((time.time() - T0) / period * 2 * math.pi + phase)


def cycle(period: float, duty: float, offset: float = 0.0) -> bool:
    """True for `duty` fraction of every `period` seconds."""
    return ((time.time() - T0 + offset) % period) < period * duty


@dataclass
class PortSim:
    name: str
    speed: float  # Mbps
    load: float  # typical utilization 0..1
    media: str = "copper"
    alias: str = ""
    up: bool = True
    uplink: bool = False
    flap: tuple[float, float] | None = None  # (period, duty-down)
    err_rate: float = 0.0  # errors/s while cycle active
    poe: float | None = None
    phase: float = field(default_factory=lambda: random.random() * 6)
    rx: int = field(default_factory=lambda: random.randint(10**9, 10**12))
    tx: int = field(default_factory=lambda: random.randint(10**9, 10**12))
    errs: int = 0
    last: float = field(default_factory=time.time)

    def tick(self) -> Interface:
        now = time.time()
        dt, self.last = max(0.0, now - self.last), now
        up = self.up and not (self.flap and cycle(self.flap[0], self.flap[1], self.phase * 50))
        if up:
            base = self.speed * 1e6 / 8 * self.load
            burst = 3.0 if random.random() < 0.04 else 1.0
            rx_rate = base * (0.35 + 0.65 * wave(600, self.phase)) * burst * random.uniform(0.85, 1.15)
            tx_rate = rx_rate * random.uniform(0.15, 0.6)
            self.rx += int(min(rx_rate, self.speed * 1e6 / 8 * 0.97) * dt)
            self.tx += int(min(tx_rate, self.speed * 1e6 / 8 * 0.97) * dt)
            if self.err_rate and cycle(900, 0.4, self.phase * 30):
                self.errs += int(self.err_rate * dt * random.uniform(0.5, 1.5))
        return Interface(
            name=self.name, alias=self.alias, oper_up=up, admin_up=True, speed_mbps=self.speed if up else None,
            media=self.media, in_octets=self.rx, out_octets=self.tx, in_errors=self.errs, out_errors=0,
            is_uplink=self.uplink, poe_w=(self.poe * random.uniform(0.9, 1.1)) if self.poe and up else None,
            mac=mac_for(self.name, self.alias),
        )


LOG_TEMPLATES: dict[str, list[tuple[int, str, str]]] = {
    "pfsense": [
        (5, "filterlog", "5,,,1000000103,igb0,match,block,in,4,0x0,,64,0,0,DF,6,tcp,60,{ip},10.0.0.1,51234,22,0,S"),
        (6, "dhcpd", "DHCPACK on 10.0.10.{n} to {mac} via ix0"),
        (6, "openvpn", "user 'roadwarrior' authenticated"),
        (4, "dpinger", "WAN_DHCP {gw}: Alarm latency 48ms stddev 12ms loss 0%"),
        (6, "unbound", "[66:0] info: generate keytag query _ta-4f66. NULL IN"),
        (3, "php-fpm", "/rc.newwanip: rc.newwanip: on (IP address: {ip}) (interface: WAN[wan]) (real interface: igb0)."),
    ],
    "opnsense": [
        (6, "configd.py", "[c5a1] generate template container OPNsense/Syslog"),
        (4, "kernel", "vtnet1: link state changed to DOWN"),
        (6, "kernel", "vtnet1: link state changed to UP"),
        (5, "suricata", "[Drop] [1:2210045:2] SURICATA STREAM Packet with invalid ack from {ip}"),
        (6, "sshd", "Accepted publickey for root from 10.0.0.42 port 52113 ssh2"),
    ],
    "procurve": [
        (6, "ports", "port {port} is now on-line"),
        (4, "FFI", "port {port}-High collision or drop rate. See help."),
        (5, "lldp", "LLDP - New neighbor detected on port {port}"),
        (6, "mgr", "SME SSH from 10.0.0.42 - MANAGER Mode"),
        (4, "stp", "MSTI 0 Root changed from 32768:{mac} to 4096:{mac}"),
    ],
    "tplink": [
        (4, "port", "Port {port} link down"),
        (6, "port", "Port {port} link up 1000M full"),
    ],
}


def fake_ip() -> str:
    return f"{random.choice([45, 89, 103, 185, 194, 203])}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"


def gen_logs(kind: str, n: int, ports: int = 8) -> list[LogLine]:
    out = []
    for _ in range(n):
        sev, app, tpl = random.choice(LOG_TEMPLATES[kind])
        out.append(LogLine(ts=time.time() - random.random() * 5, severity=sev, app=app, message=tpl.format(
            ip=fake_ip(), n=random.randint(20, 240), mac=mac_for(random.random()), gw="1.1.1.1",
            port=random.randint(1, ports))))
    return out


class DemoCollector(Collector):
    kind = "demo"
    label = "Demo device (simulated)"
    vendor = "NetworkVision"
    description = "Simulated device for demos and development. Enabled with NV_DEMO_MODE=true."
    ping_host = False
    fields = [FieldSpec(key="profile", label="Profile", type="select",
                        options=["pfsense", "opnsense", "unifi", "procurve", "tplink", "host"], default="host")]

    def __init__(self, host: str, config: dict[str, Any], secrets: dict[str, Any]) -> None:
        super().__init__(host, config, secrets)
        self.profile = str(self.opt("profile"))
        self.name = str(config.get("demo_name", host))
        self.ports = self._build_ports()
        self.children_state: dict[str, list[PortSim]] = {}

    # ------------------------------------------------------------------ ports
    def _build_ports(self) -> list[PortSim]:
        p = self.profile
        if p == "pfsense":
            return [PortSim("WAN", 1000, 0.25, alias="igb0", uplink=True), PortSim("LAN", 10000, 0.06, "sfp+", "ix0"),
                    PortSim("DMZ", 1000, 0.05, alias="igb1"), PortSim("IOT", 1000, 0.02, alias="igb1.30"),
                    PortSim("WG0", 1000, 0.01, "virtual", "wg0")]
        if p == "opnsense":
            return [PortSim("WAN", 10000, 0.03, "virtual", "vtnet0"),
                    PortSim("LAB", 10000, 0.04, "virtual", "vtnet1", flap=(1800, 0.02))]
        if p == "procurve":
            ports = [PortSim(str(i), 1000, random.uniform(0.0, 0.12), up=random.random() > 0.35,
                             poe=random.choice([None, None, 4.2, 6.8, 12.1])) for i in range(1, 49)]
            ports[16].err_rate, ports[16].up, ports[16].alias = 6.0, True, "Lab-NUC"
            ports[0].up, ports[0].alias = True, "Desk-SW"
            ports[1].up, ports[1].alias = True, "Garage-SW"
            ports += [PortSim(str(i), 10000, 0.08, "sfp+", "Uplink-Core" if i == 49 else "", up=i == 49, uplink=i == 49)
                      for i in range(49, 53)]
            return ports
        if p == "tplink":
            flapping = "garage" in self.name.lower()
            return [PortSim(f"Port {i}", 1000, random.uniform(0.0, 0.2), up=i in (1, 2, 3, 5, 8), uplink=i == 8,
                            flap=(420, 0.12) if flapping and i == 3 else None) for i in range(1, 9)]
        if p == "host":
            return [PortSim("eth0", 10000 if "nas" in self.name.lower() else 1000, 0.08)]
        return []

    # --------------------------------------------------------------- collect
    async def collect(self) -> Snapshot:
        builder = getattr(self, f"_{self.profile}", self._host)
        return builder()

    def _base(self, cpu: float, mem: float, temp: float | None = None) -> Snapshot:
        s = Snapshot()
        s.interfaces = [p.tick() for p in self.ports]
        s.metrics = {"cpu": round(cpu, 1), "mem": round(mem, 1), "uptime_s": time.time() - T0 + 86400 * 23}
        if temp is not None:
            s.metrics["temp"] = round(temp, 1)
        return s

    def _pfsense(self) -> Snapshot:
        s = self._base(8 + 25 * wave(500) + random.uniform(-3, 3), 34 + 4 * wave(2000), 46 + 6 * wave(700))
        s.facts = {"vendor": "Netgate", "model": "Netgate 6100", "version": "2.8.0-RELEASE", "serial": "NG-DEMO-6100",
                   "cpu_model": "Intel Atom C3558R @ 2.20GHz", "cpu_count": 4}
        spike = cycle(1500, 0.08, 200)
        s.gateways = [
            Gateway("WAN_DHCP", "1.1.1.1", True, round((68 if spike else 11) + random.uniform(-2, 4), 1),
                    round(random.uniform(8, 20) if spike else 0.0, 1), "high latency" if spike else ""),
            Gateway("WAN_DHCP6", "2606:4700::1111", True, round(13 + random.uniform(-2, 3), 1), 0.0),
            Gateway("WG_VPS", "10.66.0.1", True, round(34 + random.uniform(-3, 6), 1), 0.0),
        ]
        s.metrics["clients"] = 87 + int(10 * wave(3000))
        s.logs = gen_logs("pfsense", random.randint(1, 4)) + demo_firewall.pfsense_filterlog()
        s.sections = [
            demo_firewall.rules_section(),
            Section("services", "Services", ["Service", "Description", "Running"], [
                ["unbound", "DNS Resolver", True], ["dhcpd", "DHCP Server", True], ["ntpd", "NTP", True],
                ["wireguard", "WireGuard", True], ["pfBlockerNG", "pfBlockerNG", not cycle(3600, 0.05)]]),
        ]
        return s

    def _opnsense(self) -> Snapshot:
        hot = cycle(1200, 0.18, 400)
        s = self._base((92 + random.uniform(0, 6)) if hot else 6 + 10 * wave(300), 41 + 5 * wave(900))
        s.facts = {"vendor": "Deciso", "model": "OPNsense (Proxmox VM)", "version": "26.7.2", "updates_available": True}
        s.gateways = [Gateway("LAB_GW", "10.0.0.1", True, round(0.4 + random.uniform(0, 0.3), 2), 0.0)]
        s.logs = gen_logs("opnsense", random.randint(0, 2))
        if hot and random.random() < 0.3:
            s.logs.append(LogLine(time.time(), "suricata: CPU usage high, packet drops on vtnet1", 3, "suricata"))
        s.sections = [Section("firmware", "Firmware", kind="kv", rows=[
            ["Product", "OPNsense"], ["Version", "26.7.2"], ["Status", "Update available: 26.7.3"]])]
        return s

    def _procurve(self) -> Snapshot:
        s = self._base(4 + 8 * wave(800), 22 + random.uniform(-1, 1), 39 + 3 * wave(1000))
        s.facts = {"vendor": "HP ProCurve", "model": "J9729A 2920-48G-PoE+", "version": "WB.16.10.0025",
                   "hostname": self.name, "description": "HP J9729A 2920-48G-POE+ Switch, revision WB.16.10.0025"}
        s.neighbors = [Neighbor("49", "Core-10G", "Port 9", protocol="lldp")]
        s.logs = gen_logs("procurve", random.randint(0, 2), 48)
        s.sections = [Section("vlans", "VLANs", ["VLAN ID", "Name"], [[1, "DEFAULT_VLAN"], [10, "LAN"], [30, "IOT"],
                                                                     [50, "LAB"], [99, "MGMT"]])]
        return s

    def _tplink(self) -> Snapshot:
        s = self._base(0, 0)
        s.metrics = {"uptime_s": time.time() - T0 + 86400 * 4}
        s.facts = {"vendor": "TP-Link", "model": "TL-SG108E", "hardware": "TL-SG108E 6.0", "version": "1.0.0 Build 20230218"}
        s.logs = gen_logs("tplink", 1) if random.random() < 0.2 else []
        return s

    def _host(self) -> Snapshot:
        s = self._base(10 + 30 * wave(400, len(self.name)), 50 + 20 * wave(1500), None)
        s.metrics["latency_ms"] = round(random.uniform(0.2, 0.9), 2)
        s.metrics["loss_pct"] = 0.0
        s.facts = {"vendor": "", "model": self.config.get("demo_model", "Server")}
        return s

    def _unifi(self) -> Snapshot:
        s = Snapshot()
        s.facts = {"vendor": "Ubiquiti", "model": "UniFi Cloud Key Gen2 Plus", "version": "9.4.19", "site": "default"}
        s.metrics = {"cpu": round(12 + 10 * wave(300), 1), "mem": round(61 + 3 * wave(800), 1),
                     "temp": round(52 + 4 * wave(600), 1), "clients": 64 + int(12 * wave(2400))}
        s.gateways = [Gateway("Internet", "pf-edge", True, round(12 + random.uniform(-1, 3), 1), 0.0,
                              "down 940 / up 38 Mbps (speedtest)")]
        core_ports = (
            [PortSim(f"Port {i}", 10000, random.uniform(0.02, 0.18), "sfp+", up=i in (1, 2, 3, 4, 5, 9, 12)) for i in range(1, 13)]
            + [PortSim(f"Port {i}", 10000, 0.05, "copper", up=i in (13, 14)) for i in range(13, 17)]
        )
        core_ports[0].alias, core_ports[0].uplink = "pf-edge LAN", True
        core_ports[1].alias, core_ports[2].alias = "Proxmox-01", "TrueNAS"
        core_ports[3].alias, core_ports[8].alias = "Proxmox-02", "Access-SW1"
        children = [
            ("Core-10G", "US-16-XG", "switch", "10.0.0.10", core_ports, None, None),
            ("U6-Pro Living Room", "U6-Pro", "ap", "10.0.0.21",
             [PortSim("Port 1", 1000, 0.08, uplink=True, poe=13.2)], "Access-SW1", "Port 5"),
            ("U6-LR Office", "U6-LR", "ap", "10.0.0.22",
             [PortSim("Port 1", 1000, 0.05, uplink=True, poe=11.8)], "Access-SW1", "Port 6"),
            ("U6-Mesh Garage", "U6-Mesh", "ap", "10.0.0.23",
             [PortSim("Port 1", 1000, 0.02, uplink=True)], "Garage-SW", "Port 4"),
        ]
        for name, model, role, ip, ports, up_name, up_port in children:
            ports = self.children_state.setdefault(name, ports)
            mac = mac_for("unifi", name)
            offline = name.startswith("U6-Mesh") and cycle(1500, 0.12, 900)
            c = ChildSnapshot(external_id=mac, name=name, role=role, host=ip, reachable=not offline,
                              error="UniFi state: heartbeat missed" if offline else None)
            c.facts = {"vendor": "Ubiquiti", "model": model, "mac": mac, "version": "7.1.26" if role == "switch" else "6.7.31",
                       "upgradable": name == "U6-LR Office", "upgrade_to": "6.7.35" if name == "U6-LR Office" else ""}
            if not offline:
                c.interfaces = [p.tick() for p in ports]
                c.metrics = {"cpu": round(random.uniform(3, 18), 1), "mem": round(random.uniform(30, 60), 1),
                             "uptime_s": time.time() - T0 + 86400 * 11}
                if role == "switch":
                    c.metrics["temp"] = round(55 + 6 * wave(700), 1)
                else:
                    c.metrics["clients"] = random.randint(6, 28)
                    c.metrics["satisfaction"] = random.randint(88, 99)
            if up_name:
                c.neighbors = [Neighbor("Port 1", up_name, up_port, protocol="uplink")]
            s.children.append(c)
        if random.random() < 0.25:
            s.logs.append(LogLine(time.time(), random.choice([
                "User[iPhone-14] roams from AP[U6-Pro Living Room] to AP[U6-LR Office]",
                "Guest[Pixel-8] connected to SSID \"Guests\"",
                "AP[U6-Mesh Garage] was disconnected", "Switch[Core-10G] port 5 STP state forwarding",
            ]), 6, "evt", "unifi"))
        from .demo_wifi import demo_unifi_data  # local import: demo_wifi imports the UniFi collector

        offline_aps = {c.name for c in s.children if not c.reachable}
        s.clients, s.wifi = demo_unifi_data({c.name: c.external_id for c in s.children},
                                            mac_for("unifi", "Core-10G"), offline_aps)
        s.metrics["clients"] = sum(1 for c in s.clients if c["online"])
        s.sections = [Section("networks", "Networks / VLANs", ["Name", "Purpose", "VLAN", "Subnet", "DHCP", "Enabled"], [
            ["LAN", "corporate", "", "10.0.0.1/24", False, True], ["IoT", "corporate", 30, "10.0.30.1/24", False, True],
            ["Lab", "corporate", 50, "10.0.50.1/24", False, True], ["Guests", "guest", 70, "10.0.70.1/24", True, True]])]
        return s

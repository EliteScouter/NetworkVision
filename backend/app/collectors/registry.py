"""Collector registry - the single list of supported integrations."""

from __future__ import annotations

from typing import Any

from ..config import get_settings
from .base import Collector
from .demo import DemoCollector
from .opnsense import OpnSenseCollector
from .pfsense import PfSenseCollector
from .ping import PingCollector
from .snmp import SnmpCollector
from .tplink import TplinkEasySmartCollector
from .unifi import UnifiCollector
from .windows_dhcp import WindowsDhcpCollector

COLLECTORS: dict[str, type[Collector]] = {
    c.kind: c
    for c in (
        PfSenseCollector,
        OpnSenseCollector,
        UnifiCollector,
        SnmpCollector,
        WindowsDhcpCollector,
        TplinkEasySmartCollector,
        PingCollector,
        DemoCollector,
    )
}


def available() -> list[dict[str, Any]]:
    demo = get_settings().demo_mode
    return [c.describe() for k, c in COLLECTORS.items() if k != "demo" or demo]


def build(kind: str, host: str, config: dict[str, Any], secrets: dict[str, Any]) -> Collector:
    cls = COLLECTORS.get(kind)
    if cls is None:
        raise ValueError(f"Unknown collector kind: {kind}")
    return cls(host, config, secrets)

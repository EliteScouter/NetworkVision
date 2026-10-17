"""Collector contract.

A collector talks to one *integration endpoint* (a firewall, a switch, a UniFi
controller...) and returns a normalized :class:`Snapshot`. Everything vendor
specific stays inside the collector; the rest of NetworkVision (rates, alerts,
topology, UI) only ever sees this normalized shape.

Adding a new integration = subclass :class:`Collector`, declare ``fields`` for
the UI form, implement :meth:`collect`, and register it in ``registry.py``.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, ClassVar, Literal

from pydantic import BaseModel


class FieldSpec(BaseModel):
    key: str
    label: str
    type: Literal["text", "number", "password", "bool", "select"] = "text"
    secret: bool = False
    required: bool = False
    default: Any = None
    options: list[str] | None = None
    placeholder: str = ""
    help: str = ""


@dataclass
class Interface:
    name: str
    alias: str = ""
    index: int | None = None
    oper_up: bool | None = None
    admin_up: bool | None = None
    speed_mbps: float | None = None
    mac: str = ""
    media: str = ""  # copper | sfp | sfp+ | wifi | virtual ...
    # Either raw counters (rates computed by NetworkVision) ...
    in_octets: int | None = None
    out_octets: int | None = None
    in_errors: int | None = None
    out_errors: int | None = None
    in_discards: int | None = None
    out_discards: int | None = None
    # ... or rates computed by the device itself.
    rx_bps: float | None = None
    tx_bps: float | None = None
    poe_w: float | None = None
    vlan: str = ""
    is_uplink: bool = False
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class Neighbor:
    local_port: str = ""
    remote_name: str = ""
    remote_port: str = ""
    remote_mac: str = ""
    remote_ip: str = ""
    protocol: str = "lldp"  # lldp | cdp | uplink | arp


@dataclass
class Gateway:
    name: str
    address: str = ""
    up: bool | None = None
    latency_ms: float | None = None
    loss_pct: float | None = None
    detail: str = ""


@dataclass
class LogLine:
    ts: float
    message: str
    severity: int = 6
    app: str = ""
    facility: str = ""
    naive: bool = False  # timestamp had no timezone (corrected with the sender's learned offset)


@dataclass
class Section:
    """Arbitrary vendor data (settings, leases, rules, VLANs...) rendered generically."""

    id: str
    title: str
    columns: list[str] = field(default_factory=list)
    rows: list[list[Any]] = field(default_factory=list)
    kind: Literal["table", "kv"] = "table"


@dataclass
class Snapshot:
    reachable: bool = True
    error: str | None = None
    metrics: dict[str, float | int | None] = field(default_factory=dict)
    facts: dict[str, Any] = field(default_factory=dict)
    interfaces: list[Interface] = field(default_factory=list)
    neighbors: list[Neighbor] = field(default_factory=list)
    gateways: list[Gateway] = field(default_factory=list)
    logs: list[LogLine] = field(default_factory=list)
    sections: list[Section] = field(default_factory=list)
    children: list[ChildSnapshot] = field(default_factory=list)
    #: Network clients seen by this integration (see services/clients.py for the field set).
    clients: list[dict[str, Any]] = field(default_factory=list)
    #: Wireless overview from a controller: {"aps": [...], "ssids": [...], "neighbors": [...]}.
    wifi: dict[str, Any] = field(default_factory=dict)
    #: DHCP server configuration (Windows DHCP): scopes, failover, options... see collectors/windows_dhcp.py.
    dhcp_server: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ChildSnapshot(Snapshot):
    """A device discovered *through* an integration (e.g. a switch adopted by UniFi)."""

    external_id: str = ""
    name: str = ""
    role: str = "other"
    host: str = ""


class CollectorError(Exception):
    """Raised for expected, user-actionable failures (bad credentials, unreachable...)."""


class Collector:
    kind: ClassVar[str] = ""
    label: ClassVar[str] = ""
    vendor: ClassVar[str] = ""
    description: ClassVar[str] = ""
    default_role: ClassVar[str] = "other"
    fields: ClassVar[list[FieldSpec]] = []
    #: True if this collector discovers child devices (controllers).
    discovers_children: ClassVar[bool] = False
    #: Whether NetworkVision should also ICMP-ping the host for latency/loss.
    ping_host: ClassVar[bool] = True

    def __init__(self, host: str, config: dict[str, Any], secrets: dict[str, Any]) -> None:
        self.host = host
        self.config = config
        self.secrets = secrets

    def opt(self, key: str, default: Any = None) -> Any:
        value = self.secrets.get(key, self.config.get(key))
        if value not in (None, ""):
            return value
        if default is None:
            default = next((f.default for f in self.fields if f.key == key), None)
        return default

    async def collect(self) -> Snapshot:  # pragma: no cover - interface
        raise NotImplementedError

    async def close(self) -> None:
        """Release sessions/sockets. Called when the device is edited or removed."""

    @classmethod
    def describe(cls) -> dict[str, Any]:
        return {
            "kind": cls.kind,
            "label": cls.label,
            "vendor": cls.vendor,
            "description": cls.description,
            "default_role": cls.default_role,
            "discovers_children": cls.discovers_children,
            "fields": [f.model_dump() for f in cls.fields],
        }


def to_float(v: Any) -> float | None:
    try:
        if v is None or v == "":
            return None
        return float(str(v).strip().rstrip("%"))
    except (TypeError, ValueError):
        return None


def to_int(v: Any) -> int | None:
    f = to_float(v)
    return None if f is None else int(f)


def norm_mac(mac: str | None) -> str:
    if not mac:
        return ""
    hexes = "".join(c for c in str(mac).lower() if c in "0123456789abcdef")
    if len(hexes) != 12:
        return str(mac).lower()
    return ":".join(hexes[i : i + 2] for i in range(0, 12, 2))

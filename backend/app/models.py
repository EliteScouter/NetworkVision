"""ORM models. Timestamps are UNIX epoch floats (UTC) for portability and speed."""

from __future__ import annotations

import time
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    Double,
    ForeignKey,
    Index,
    Integer,
    SmallInteger,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base

# SQLite only auto-increments INTEGER PRIMARY KEY, so map BIGINT -> INTEGER there.
BigId = BigInteger().with_variant(Integer, "sqlite")


def now() -> float:
    return time.time()


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(128))
    kind: Mapped[str] = mapped_column(String(32), index=True)  # collector id
    role: Mapped[str] = mapped_column(String(32), default="other")
    host: Mapped[str] = mapped_column(String(255), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    poll_interval: Mapped[int | None] = mapped_column(Integer, nullable=True)
    config: Mapped[dict] = mapped_column(JSON, default=dict)  # non-secret settings
    secrets_enc: Mapped[str | None] = mapped_column(Text, nullable=True)  # Fernet blob
    parent_id: Mapped[int | None] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), nullable=True, index=True
    )
    external_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    location: Mapped[str] = mapped_column(String(128), default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    facts: Mapped[dict] = mapped_column(JSON, default=dict)
    pos_x: Mapped[float | None] = mapped_column(Double, nullable=True)
    pos_y: Mapped[float | None] = mapped_column(Double, nullable=True)
    last_seen: Mapped[float | None] = mapped_column(Double, nullable=True)
    created_at: Mapped[float] = mapped_column(Double, default=now)
    updated_at: Mapped[float] = mapped_column(Double, default=now, onupdate=now)

    __table_args__ = (Index("ix_devices_parent_ext", "parent_id", "external_id"),)


class Link(Base):
    """A manually defined topology link (auto-discovered links live in memory)."""

    __tablename__ = "links"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    a_device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"))
    a_port: Mapped[str] = mapped_column(String(64), default="")
    b_device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"))
    b_port: Mapped[str] = mapped_column(String(64), default="")
    label: Mapped[str] = mapped_column(String(128), default="")
    created_at: Mapped[float] = mapped_column(Double, default=now)


class DeviceMetric(Base):
    __tablename__ = "device_metrics"

    id: Mapped[int] = mapped_column(BigId, primary_key=True, autoincrement=True)
    ts: Mapped[float] = mapped_column(Double)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"))
    status: Mapped[int] = mapped_column(SmallInteger, default=1)  # 1 up, 0 down
    cpu: Mapped[float | None] = mapped_column(Double, nullable=True)
    mem: Mapped[float | None] = mapped_column(Double, nullable=True)
    temp: Mapped[float | None] = mapped_column(Double, nullable=True)
    latency_ms: Mapped[float | None] = mapped_column(Double, nullable=True)
    loss_pct: Mapped[float | None] = mapped_column(Double, nullable=True)
    rx_bps: Mapped[float | None] = mapped_column(Double, nullable=True)
    tx_bps: Mapped[float | None] = mapped_column(Double, nullable=True)
    clients: Mapped[int | None] = mapped_column(Integer, nullable=True)

    __table_args__ = (Index("ix_devmetrics_dev_ts", "device_id", "ts"),)


class InterfaceMetric(Base):
    __tablename__ = "interface_metrics"

    id: Mapped[int] = mapped_column(BigId, primary_key=True, autoincrement=True)
    ts: Mapped[float] = mapped_column(Double)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"))
    ifname: Mapped[str] = mapped_column(String(64))
    rx_bps: Mapped[float] = mapped_column(Double, default=0)
    tx_bps: Mapped[float] = mapped_column(Double, default=0)
    errors_per_min: Mapped[float] = mapped_column(Double, default=0)
    util_pct: Mapped[float | None] = mapped_column(Double, nullable=True)

    __table_args__ = (Index("ix_ifmetrics_dev_if_ts", "device_id", "ifname", "ts"),)


class LogEntry(Base):
    __tablename__ = "logs"

    id: Mapped[int] = mapped_column(BigId, primary_key=True, autoincrement=True)
    ts: Mapped[float] = mapped_column(Double, index=True)
    device_id: Mapped[int | None] = mapped_column(
        ForeignKey("devices.id", ondelete="SET NULL"), nullable=True
    )
    host: Mapped[str] = mapped_column(String(255), default="")
    severity: Mapped[int] = mapped_column(SmallInteger, default=6)  # RFC5424 0..7
    facility: Mapped[str] = mapped_column(String(32), default="")
    app: Mapped[str] = mapped_column(String(64), default="")
    message: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(16), default="syslog")  # syslog | api | system

    __table_args__ = (
        Index("ix_logs_dev_ts", "device_id", "ts"),
        Index("ix_logs_sev_ts", "severity", "ts"),
    )


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    key: Mapped[str] = mapped_column(String(255), index=True)  # rule:device:subject
    device_id: Mapped[int | None] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), nullable=True, index=True
    )
    rule: Mapped[str] = mapped_column(String(64))
    severity: Mapped[str] = mapped_column(String(16), default="warning")
    title: Mapped[str] = mapped_column(String(255))
    detail: Mapped[str] = mapped_column(Text, default="")
    started_at: Mapped[float] = mapped_column(Double, default=now)
    last_seen_at: Mapped[float] = mapped_column(Double, default=now)
    resolved_at: Mapped[float | None] = mapped_column(Double, nullable=True, index=True)
    acknowledged_at: Mapped[float | None] = mapped_column(Double, nullable=True)
    acknowledged_by: Mapped[str] = mapped_column(String(64), default="")
    count: Mapped[int] = mapped_column(Integer, default=1)


class Setting(Base):
    """Small key/value store for runtime state (e.g. MFA). Sensitive values are stored encrypted."""

    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text, default="")
    updated_at: Mapped[float] = mapped_column(Double, default=now, onupdate=now)


# --------------------------------------------------------------------------- #
# Additional time series. Raw rows are kept NV_RETENTION_DAYS_METRICS; the
# *_hourly rollups (avg + max per hour) are kept NV_RETENTION_DAYS_ROLLUP so long
# ranges (30 days, a year) stay fast and small.
# --------------------------------------------------------------------------- #
class GatewayMetric(Base):
    __tablename__ = "gateway_metrics"

    id: Mapped[int] = mapped_column(BigId, primary_key=True, autoincrement=True)
    ts: Mapped[float] = mapped_column(Double)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(64))
    up: Mapped[int | None] = mapped_column(SmallInteger, nullable=True)
    latency_ms: Mapped[float | None] = mapped_column(Double, nullable=True)
    loss_pct: Mapped[float | None] = mapped_column(Double, nullable=True)

    __table_args__ = (Index("ix_gwmetrics_dev_name_ts", "device_id", "name", "ts"),)


class RadioMetric(Base):
    """One WiFi radio (AP + band) sample."""

    __tablename__ = "radio_metrics"

    id: Mapped[int] = mapped_column(BigId, primary_key=True, autoincrement=True)
    ts: Mapped[float] = mapped_column(Double)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"))  # the AP
    radio: Mapped[str] = mapped_column(String(16))  # 2.4 | 5 | 6
    channel: Mapped[int | None] = mapped_column(Integer, nullable=True)
    utilization: Mapped[float | None] = mapped_column(Double, nullable=True)
    interference: Mapped[float | None] = mapped_column(Double, nullable=True)
    clients: Mapped[int | None] = mapped_column(Integer, nullable=True)
    satisfaction: Mapped[float | None] = mapped_column(Double, nullable=True)
    retries_pct: Mapped[float | None] = mapped_column(Double, nullable=True)

    __table_args__ = (Index("ix_radiometrics_dev_radio_ts", "device_id", "radio", "ts"),)


class SpeedtestResult(Base):
    __tablename__ = "speedtest_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[float] = mapped_column(Double, index=True)
    engine: Mapped[str] = mapped_column(String(32), default="cloudflare")
    trigger: Mapped[str] = mapped_column(String(16), default="schedule")  # schedule | manual
    server: Mapped[str] = mapped_column(String(128), default="")
    isp: Mapped[str] = mapped_column(String(128), default="")
    public_ip: Mapped[str] = mapped_column(String(64), default="")
    download_bps: Mapped[float | None] = mapped_column(Double, nullable=True)
    upload_bps: Mapped[float | None] = mapped_column(Double, nullable=True)
    latency_ms: Mapped[float | None] = mapped_column(Double, nullable=True)
    jitter_ms: Mapped[float | None] = mapped_column(Double, nullable=True)
    loaded_latency_ms: Mapped[float | None] = mapped_column(Double, nullable=True)
    bytes_used: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    duration_s: Mapped[float | None] = mapped_column(Double, nullable=True)
    error: Mapped[str] = mapped_column(Text, default="")


def _hourly(name: str, keys: dict[str, Any], values: list[str]) -> type:
    """Build an hourly rollup model: keys + ts (hour start) + <value>_avg / <value>_max."""
    attrs: dict[str, Any] = {
        "__tablename__": name,
        "id": mapped_column(BigId, primary_key=True, autoincrement=True),
        "ts": mapped_column(Double),
        "samples": mapped_column(Integer, default=0),
        "__annotations__": {},
    }
    for k, col in keys.items():
        attrs[k] = col
    for v in values:
        attrs[f"{v}_avg"] = mapped_column(Double, nullable=True)
        attrs[f"{v}_max"] = mapped_column(Double, nullable=True)
    attrs["__table_args__"] = (Index(f"ix_{name}_keys_ts", *keys.keys(), "ts"),)
    return type(name.title().replace("_", ""), (Base,), attrs)


DEVICE_VALUES = ["status", "cpu", "mem", "temp", "latency_ms", "loss_pct", "rx_bps", "tx_bps", "clients"]
INTERFACE_VALUES = ["rx_bps", "tx_bps", "errors_per_min", "util_pct"]
GATEWAY_VALUES = ["up", "latency_ms", "loss_pct"]
RADIO_VALUES = ["utilization", "interference", "clients", "satisfaction", "retries_pct"]

DeviceMetricHourly = _hourly("device_metrics_hourly", {
    "device_id": mapped_column(ForeignKey("devices.id", ondelete="CASCADE"))}, DEVICE_VALUES)
InterfaceMetricHourly = _hourly("interface_metrics_hourly", {
    "device_id": mapped_column(ForeignKey("devices.id", ondelete="CASCADE")),
    "ifname": mapped_column(String(64))}, INTERFACE_VALUES)
GatewayMetricHourly = _hourly("gateway_metrics_hourly", {
    "device_id": mapped_column(ForeignKey("devices.id", ondelete="CASCADE")),
    "name": mapped_column(String(64))}, GATEWAY_VALUES)
RadioMetricHourly = _hourly("radio_metrics_hourly", {
    "device_id": mapped_column(ForeignKey("devices.id", ondelete="CASCADE")),
    "radio": mapped_column(String(16))}, RADIO_VALUES)

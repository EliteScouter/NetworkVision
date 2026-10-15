"""ORM models. Timestamps are UNIX epoch floats (UTC) for portability and speed."""

from __future__ import annotations

import time

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    Float,
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
    pos_x: Mapped[float | None] = mapped_column(Float, nullable=True)
    pos_y: Mapped[float | None] = mapped_column(Float, nullable=True)
    last_seen: Mapped[float | None] = mapped_column(Float, nullable=True)
    created_at: Mapped[float] = mapped_column(Float, default=now)
    updated_at: Mapped[float] = mapped_column(Float, default=now, onupdate=now)

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
    created_at: Mapped[float] = mapped_column(Float, default=now)


class DeviceMetric(Base):
    __tablename__ = "device_metrics"

    id: Mapped[int] = mapped_column(BigId, primary_key=True, autoincrement=True)
    ts: Mapped[float] = mapped_column(Float)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"))
    status: Mapped[int] = mapped_column(SmallInteger, default=1)  # 1 up, 0 down
    cpu: Mapped[float | None] = mapped_column(Float, nullable=True)
    mem: Mapped[float | None] = mapped_column(Float, nullable=True)
    temp: Mapped[float | None] = mapped_column(Float, nullable=True)
    latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    loss_pct: Mapped[float | None] = mapped_column(Float, nullable=True)
    rx_bps: Mapped[float | None] = mapped_column(Float, nullable=True)
    tx_bps: Mapped[float | None] = mapped_column(Float, nullable=True)
    clients: Mapped[int | None] = mapped_column(Integer, nullable=True)

    __table_args__ = (Index("ix_devmetrics_dev_ts", "device_id", "ts"),)


class InterfaceMetric(Base):
    __tablename__ = "interface_metrics"

    id: Mapped[int] = mapped_column(BigId, primary_key=True, autoincrement=True)
    ts: Mapped[float] = mapped_column(Float)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"))
    ifname: Mapped[str] = mapped_column(String(64))
    rx_bps: Mapped[float] = mapped_column(Float, default=0)
    tx_bps: Mapped[float] = mapped_column(Float, default=0)
    errors_per_min: Mapped[float] = mapped_column(Float, default=0)
    util_pct: Mapped[float | None] = mapped_column(Float, nullable=True)

    __table_args__ = (Index("ix_ifmetrics_dev_if_ts", "device_id", "ifname", "ts"),)


class LogEntry(Base):
    __tablename__ = "logs"

    id: Mapped[int] = mapped_column(BigId, primary_key=True, autoincrement=True)
    ts: Mapped[float] = mapped_column(Float, index=True)
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
    started_at: Mapped[float] = mapped_column(Float, default=now)
    last_seen_at: Mapped[float] = mapped_column(Float, default=now)
    resolved_at: Mapped[float | None] = mapped_column(Float, nullable=True, index=True)
    acknowledged_at: Mapped[float | None] = mapped_column(Float, nullable=True)
    acknowledged_by: Mapped[str] = mapped_column(String(64), default="")
    count: Mapped[int] = mapped_column(Integer, default=1)

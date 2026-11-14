from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from app.schemas.event import SecurityEvent

JSONType = JSON().with_variant(JSONB(), "postgresql")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class RawEventRecord(Base):
    """Intake ledger: one row per unique source record, including ones that failed to normalize."""

    __tablename__ = "raw_events"
    __table_args__ = (
        UniqueConstraint("event_source", "source_event_id", name="uq_raw_events_source_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_source: Mapped[str] = mapped_column(String(32))
    source_event_id: Mapped[str] = mapped_column(String(128))
    storage_reference: Mapped[str] = mapped_column(Text)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(16), default="normalized")  # normalized|skipped|failed
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SecurityEventRecord(Base):
    __tablename__ = "security_events"
    __table_args__ = (
        Index("ix_security_events_actor_time", "actor_id", "timestamp"),
        Index("ix_security_events_layer_time", "layer", "timestamp"),
    )

    event_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    cloud_provider: Mapped[str] = mapped_column(String(16))
    account_id: Mapped[str | None] = mapped_column(String(32))
    region: Mapped[str | None] = mapped_column(String(32))

    event_source: Mapped[str] = mapped_column(String(32))
    source_event_id: Mapped[str] = mapped_column(String(128))
    event_name: Mapped[str] = mapped_column(String(128))
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    layer: Mapped[str] = mapped_column(String(16))
    action: Mapped[str] = mapped_column(String(160))
    outcome: Mapped[str] = mapped_column(String(16))
    error_code: Mapped[str | None] = mapped_column(String(128))

    actor_id: Mapped[str | None] = mapped_column(String(256))
    actor_type: Mapped[str | None] = mapped_column(String(32))
    session_id: Mapped[str | None] = mapped_column(String(128), index=True)
    access_key_id: Mapped[str | None] = mapped_column(String(128), index=True)

    source_ip: Mapped[str | None] = mapped_column(String(64), index=True)
    destination_ip: Mapped[str | None] = mapped_column(String(64), index=True)
    source_port: Mapped[int | None] = mapped_column(Integer)
    destination_port: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[str | None] = mapped_column(String(16))

    resource_id: Mapped[str | None] = mapped_column(String(1024), index=True)
    resource_type: Mapped[str | None] = mapped_column(String(64))

    bytes_transferred: Mapped[int | None] = mapped_column(BigInteger)
    base_severity: Mapped[float] = mapped_column(Float)
    user_agent: Mapped[str | None] = mapped_column(Text)
    attributes: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)

    raw_event_id: Mapped[int] = mapped_column(ForeignKey("raw_events.id"))
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    raw: Mapped[RawEventRecord] = relationship(lazy="joined")


class CollectorCheckpoint(Base):
    __tablename__ = "collector_checkpoints"

    collector: Mapped[str] = mapped_column(String(64), primary_key=True)
    cursor_time: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


_EVIDENCE_FIELDS = {"raw_event_reference", "raw_event_hash"}
_ENUM_FIELDS = ("event_source", "layer", "outcome")


def record_from_event(event: SecurityEvent, raw: RawEventRecord) -> SecurityEventRecord:
    data = event.model_dump(exclude=_EVIDENCE_FIELDS)
    for field in _ENUM_FIELDS:
        data[field] = data[field].value
    return SecurityEventRecord(**data, raw=raw)


def event_from_record(record: SecurityEventRecord) -> SecurityEvent:
    fields = set(SecurityEvent.model_fields) - _EVIDENCE_FIELDS
    return SecurityEvent(
        **{name: getattr(record, name) for name in fields},
        raw_event_reference=record.raw.storage_reference,
        raw_event_hash=record.raw.sha256,
    )

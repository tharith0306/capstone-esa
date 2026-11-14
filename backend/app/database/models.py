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


# ---------------------------------------------------------------- analysis (Layers 5-10)


class AnalysisRun(Base):
    __tablename__ = "analysis_runs"

    run_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(16), default="running")
    model_version: Mapped[str | None] = mapped_column(String(64))
    range_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    range_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    n_events: Mapped[int] = mapped_column(Integer, default=0)
    n_windows: Mapped[int] = mapped_column(Integer, default=0)
    n_detections: Mapped[int] = mapped_column(Integer, default=0)
    n_incidents: Mapped[int] = mapped_column(Integer, default=0)
    seconds: Mapped[float | None] = mapped_column(Float)
    error: Mapped[str | None] = mapped_column(Text)


class DetectionRecord(Base):
    __tablename__ = "detections"
    __table_args__ = (Index("ix_detections_start", "start"),)

    detection_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(40), index=True)
    incident_id: Mapped[str | None] = mapped_column(String(40), index=True)
    kind: Mapped[str] = mapped_column(String(16))
    rule: Mapped[str | None] = mapped_column(String(64))
    entity: Mapped[str] = mapped_column(String(300))
    start: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    end: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    predicted_class: Mapped[str] = mapped_column(String(40))
    class_probability: Mapped[float] = mapped_column(Float)
    attack_probability: Mapped[float] = mapped_column(Float)
    anomaly_score: Mapped[float] = mapped_column(Float)
    score: Mapped[float] = mapped_column(Float)
    probabilities: Mapped[dict] = mapped_column(JSONType, default=dict)
    explanation: Mapped[dict | None] = mapped_column(JSONType)
    entities: Mapped[dict] = mapped_column(JSONType, default=dict)
    event_ids: Mapped[list] = mapped_column(JSONType, default=list)


class IncidentRecord(Base):
    __tablename__ = "incidents"

    incident_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(40), index=True)
    title: Mapped[str] = mapped_column(String(300))
    status: Mapped[str] = mapped_column(String(24), default="open")  # open|investigating|contained|resolved|false_positive
    primary_class: Mapped[str] = mapped_column(String(40))
    risk_score: Mapped[float] = mapped_column(Float, index=True)
    risk_level: Mapped[str] = mapped_column(String(16), index=True)
    start: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    end: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    alert_count: Mapped[int] = mapped_column(Integer)
    event_count: Mapped[int] = mapped_column(Integer)
    correlation_score: Mapped[float] = mapped_column(Float)
    actors: Mapped[list] = mapped_column(JSONType, default=list)
    source_ips: Mapped[list] = mapped_column(JSONType, default=list)
    resources: Mapped[list] = mapped_column(JSONType, default=list)
    access_keys: Mapped[list] = mapped_column(JSONType, default=list)
    event_ids: Mapped[list] = mapped_column(JSONType, default=list)
    links: Mapped[list] = mapped_column(JSONType, default=list)
    sequence: Mapped[list] = mapped_column(JSONType, default=list)
    risk: Mapped[dict] = mapped_column(JSONType, default=dict)
    explanation: Mapped[dict] = mapped_column(JSONType, default=dict)
    graph: Mapped[dict] = mapped_column(JSONType, default=dict)
    timeline: Mapped[list] = mapped_column(JSONType, default=list)
    mitre: Mapped[list] = mapped_column(JSONType, default=list)
    evidence_manifest: Mapped[dict] = mapped_column(JSONType, default=dict)
    analyst_notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class ResponseActionRecord(Base):
    __tablename__ = "response_actions"

    action_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    incident_id: Mapped[str] = mapped_column(String(40), index=True)
    action_type: Mapped[str] = mapped_column(String(48))
    target: Mapped[dict] = mapped_column(JSONType, default=dict)
    description: Mapped[str] = mapped_column(Text)
    rationale: Mapped[str] = mapped_column(Text)
    api_call: Mapped[str] = mapped_column(String(160))
    automatable: Mapped[bool] = mapped_column(default=False)
    reversible: Mapped[bool] = mapped_column(default=False)
    evidence_event_ids: Mapped[list] = mapped_column(JSONType, default=list)
    # proposed -> approved | rejected -> executed | failed -> rolled_back
    status: Mapped[str] = mapped_column(String(16), default="proposed", index=True)
    proposed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    decided_by: Mapped[str | None] = mapped_column(String(120))
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    decision_note: Mapped[str | None] = mapped_column(Text)
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    execution: Mapped[dict | None] = mapped_column(JSONType)
    error: Mapped[str | None] = mapped_column(Text)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(120))
    action: Mapped[str] = mapped_column(String(64))
    object_type: Mapped[str] = mapped_column(String(32))
    object_id: Mapped[str] = mapped_column(String(64), index=True)
    details: Mapped[dict] = mapped_column(JSONType, default=dict)

import json
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_evidence_store, get_ingestion_service, get_settings_dep, require_role
from app.core.config import Settings
from app.database.models import SecurityEventRecord, event_from_record
from app.evidence.store import EvidenceStore
from app.schemas.api import (
    CountBucket,
    EventPage,
    EventStatistics,
    IngestRequest,
    IngestResult,
    RawEvidence,
)
from app.schemas.event import EventSource, EvidenceRef, Layer, Outcome, SecurityEvent
from app.services.ingestion import IngestionService

router = APIRouter(prefix="/api/events", tags=["events"])

DB = Annotated[Session, Depends(get_db)]


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


@router.post("/ingest", response_model=IngestResult, dependencies=[Depends(require_role("analyst"))])
def ingest_events(
    body: IngestRequest,
    ingestion: Annotated[IngestionService, Depends(get_ingestion_service)],
    settings: Annotated[Settings, Depends(get_settings_dep)],
) -> IngestResult:
    if len(body.records) > settings.max_ingest_batch:
        raise HTTPException(
            413,
            f"batch of {len(body.records)} exceeds max_ingest_batch={settings.max_ingest_batch}",
        )
    return ingestion.ingest(body.source, body.records)


@router.get("", response_model=EventPage)
def list_events(
    db: DB,
    layer: Layer | None = None,
    source: EventSource | None = None,
    outcome: Outcome | None = None,
    event_type: str | None = None,
    actor_id: str | None = None,
    access_key_id: str | None = None,
    source_ip: str | None = None,
    resource_id: str | None = None,
    min_severity: Annotated[float | None, Query(ge=0, le=1)] = None,
    start: datetime | None = None,
    end: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> EventPage:
    E = SecurityEventRecord
    filters = []
    if layer:
        filters.append(E.layer == layer.value)
    if source:
        filters.append(E.event_source == source.value)
    if outcome:
        filters.append(E.outcome == outcome.value)
    if event_type:
        filters.append(E.event_type == event_type)
    if actor_id:
        filters.append(E.actor_id == actor_id)
    if access_key_id:
        filters.append(E.access_key_id == access_key_id)
    if source_ip:
        filters.append(E.source_ip == source_ip)
    if resource_id:
        filters.append(E.resource_id == resource_id)
    if min_severity is not None:
        filters.append(E.base_severity >= min_severity)
    if start:
        filters.append(E.timestamp >= _utc(start))
    if end:
        filters.append(E.timestamp < _utc(end))

    total = db.scalar(select(func.count()).select_from(E).where(*filters)) or 0
    rows = db.scalars(
        select(E).where(*filters).order_by(E.timestamp.desc(), E.event_id).limit(limit).offset(offset)
    ).all()
    return EventPage(total=total, limit=limit, offset=offset, items=[event_from_record(r) for r in rows])


def _buckets(db: Session, column, limit: int | None = None) -> list[CountBucket]:
    count = func.count().label("n")
    stmt = select(column, count).group_by(column).order_by(count.desc())
    if limit:
        stmt = stmt.limit(limit)
    return [CountBucket(key=str(key), count=n) for key, n in db.execute(stmt)]


@router.get("/statistics", response_model=EventStatistics)
def event_statistics(db: DB) -> EventStatistics:
    E = SecurityEventRecord
    total, first, last = db.execute(select(func.count(), func.min(E.timestamp), func.max(E.timestamp))).one()
    return EventStatistics(
        total_events=total,
        first_event_at=_utc(first),
        last_event_at=_utc(last),
        by_layer=_buckets(db, E.layer),
        by_source=_buckets(db, E.event_source),
        by_outcome=_buckets(db, E.outcome),
        top_event_types=_buckets(db, E.event_type, limit=10),
    )


def _get_record(db: Session, event_id: str) -> SecurityEventRecord:
    record = db.get(SecurityEventRecord, event_id)
    if record is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"event {event_id} not found")
    return record


@router.get("/{event_id}", response_model=SecurityEvent)
def get_event(event_id: str, db: DB) -> SecurityEvent:
    return event_from_record(_get_record(db, event_id))


@router.get("/{event_id}/raw", response_model=RawEvidence)
def get_raw_event(
    event_id: str,
    db: DB,
    store: Annotated[EvidenceStore, Depends(get_evidence_store)],
) -> RawEvidence:
    """Return the original record and whether it still matches the hash taken at ingestion."""
    record = _get_record(db, event_id)
    evidence = EvidenceRef(reference=record.raw.storage_reference, sha256=record.raw.sha256)
    try:
        raw_bytes = store.get(evidence.reference)
    except (FileNotFoundError, KeyError, ValueError):
        return RawEvidence(event_id=event_id, **evidence.model_dump(), verified=False, raw=None)
    return RawEvidence(
        event_id=event_id,
        **evidence.model_dump(),
        verified=store.verify(evidence),
        raw=json.loads(raw_bytes),
    )

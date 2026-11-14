from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.schemas.event import EventSource, SecurityEvent


class IngestRequest(BaseModel):
    source: EventSource
    records: list[dict[str, Any]] = Field(min_length=1)


class IngestResult(BaseModel):
    source: EventSource
    received: int = 0
    stored: int = 0
    duplicates: int = 0
    skipped: int = 0
    failed: int = 0
    errors: list[str] = Field(default_factory=list)
    latest_event_time: datetime | None = None


class EventPage(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[SecurityEvent]


class CountBucket(BaseModel):
    key: str
    count: int


class EventStatistics(BaseModel):
    total_events: int
    first_event_at: datetime | None
    last_event_at: datetime | None
    by_layer: list[CountBucket]
    by_source: list[CountBucket]
    by_outcome: list[CountBucket]
    top_event_types: list[CountBucket]


class RawEvidence(BaseModel):
    event_id: str
    reference: str
    sha256: str
    verified: bool
    raw: dict[str, Any] | None

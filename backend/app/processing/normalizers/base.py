from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any

from app.schemas.event import EventSource, EvidenceRef, SecurityEvent


class NormalizationError(ValueError):
    """The record cannot be turned into a SecurityEvent (malformed or unsupported)."""


class SkipRecord(Exception):
    """The record is valid but carries no security event (e.g. a VPC flow NODATA line)."""


class Normalizer(ABC):
    source: EventSource

    @abstractmethod
    def source_event_id(self, raw: dict[str, Any]) -> str:
        """The source's own unique ID for this record, used for deduplication."""

    @abstractmethod
    def normalize(self, raw: dict[str, Any], evidence: EvidenceRef) -> SecurityEvent:
        """Map a raw record to the common schema. Raises NormalizationError or SkipRecord."""


def parse_timestamp(value: Any) -> datetime:
    """Accept ISO-8601 strings, epoch seconds or epoch milliseconds; always return UTC."""
    if value is None or value == "":
        raise NormalizationError("missing timestamp")
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, (int, float)):
        seconds = value / 1000 if value > 1e11 else value
        dt = datetime.fromtimestamp(seconds, tz=timezone.utc)
    elif isinstance(value, str):
        text = value.strip()
        if text.isdigit():
            return parse_timestamp(int(text))
        try:
            dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError as exc:
            raise NormalizationError(f"unparseable timestamp {value!r}") from exc
    else:
        raise NormalizationError(f"unsupported timestamp type {type(value).__name__}")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)

from datetime import datetime, timezone
from typing import Any


def utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def row_to_dict(row: Any, exclude: set[str] | None = None) -> dict[str, Any]:
    """ORM row -> dict with timezone-aware datetimes (SQLite drops tzinfo)."""
    exclude = exclude or set()
    out = {}
    for column in row.__table__.columns:
        if column.name in exclude:
            continue
        value = getattr(row, column.name)
        out[column.name] = utc(value) if isinstance(value, datetime) else value
    return out

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.database.models import CollectorCheckpoint


def get_checkpoint(session: Session, collector: str) -> datetime | None:
    row = session.get(CollectorCheckpoint, collector)
    if row is None:
        return None
    value = row.cursor_time
    # SQLite drops tzinfo; everything CloudShield stores is UTC.
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def set_checkpoint(session: Session, collector: str, cursor: datetime) -> None:
    row = session.get(CollectorCheckpoint, collector)
    if row is None:
        session.add(CollectorCheckpoint(collector=collector, cursor_time=cursor))
    else:
        row.cursor_time = cursor
    session.commit()

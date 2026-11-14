"""Raw record -> evidence store -> normalizer -> database, with deduplication."""

import logging
from collections.abc import Iterable
from typing import Any

from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from app.database.models import RawEventRecord, record_from_event
from app.evidence.store import EvidenceStore
from app.processing.normalizers import NormalizationError, Normalizer, SkipRecord, get_normalizer
from app.schemas.api import IngestResult
from app.schemas.event import EventSource

log = logging.getLogger(__name__)

_MAX_REPORTED_ERRORS = 20


class IngestionService:
    def __init__(self, session_factory: sessionmaker[Session], store: EvidenceStore, commit_every: int = 500):
        self._session_factory = session_factory
        self._store = store
        self._commit_every = commit_every

    def ingest(self, source: EventSource, records: Iterable[Any]) -> IngestResult:
        normalizer = get_normalizer(source)
        result = IngestResult(source=source)
        seen: set[str] = set()
        pending = 0
        with self._session_factory() as session:
            try:
                for raw in records:
                    result.received += 1
                    if self._ingest_one(session, normalizer, raw, seen, result):
                        pending += 1
                    if pending >= self._commit_every:
                        session.commit()
                        pending = 0
            except SQLAlchemyError:
                session.rollback()
                raise
            except Exception:
                # A collector failed mid-stream: keep what was already processed, then surface the error.
                session.commit()
                raise
            session.commit()
        log.info(
            "ingest %s: received=%d stored=%d duplicates=%d skipped=%d failed=%d",
            source.value, result.received, result.stored, result.duplicates, result.skipped, result.failed,
        )
        return result

    def _ingest_one(
        self,
        session: Session,
        normalizer: Normalizer,
        raw: Any,
        seen: set[str],
        result: IngestResult,
    ) -> bool:
        """Returns True when rows were added to the session."""
        if not isinstance(raw, dict):
            self._fail(result, "record is not a JSON object")
            return False
        try:
            sid = normalizer.source_event_id(raw)
        except NormalizationError as exc:
            self._fail(result, str(exc))
            return False

        if sid in seen or self._exists(session, normalizer.source, sid):
            result.duplicates += 1
            return False
        seen.add(sid)

        # Evidence is preserved before normalization so even unparseable records stay recoverable.
        evidence = self._store.put(normalizer.source.value, raw)
        raw_row = RawEventRecord(
            event_source=normalizer.source.value,
            source_event_id=sid,
            storage_reference=evidence.reference,
            sha256=evidence.sha256,
        )
        session.add(raw_row)

        try:
            event = normalizer.normalize(raw, evidence)
        except SkipRecord as exc:
            raw_row.status, raw_row.error = "skipped", str(exc)
            result.skipped += 1
            return True
        except (NormalizationError, ValidationError) as exc:
            raw_row.status, raw_row.error = "failed", str(exc)[:1000]
            self._fail(result, f"{sid}: {exc}")
            return True

        session.add(record_from_event(event, raw_row))
        result.stored += 1
        if result.latest_event_time is None or event.timestamp > result.latest_event_time:
            result.latest_event_time = event.timestamp
        return True

    @staticmethod
    def _exists(session: Session, source: EventSource, sid: str) -> bool:
        stmt = select(RawEventRecord.id).where(
            RawEventRecord.event_source == source.value,
            RawEventRecord.source_event_id == sid,
        )
        return session.scalar(stmt) is not None

    @staticmethod
    def _fail(result: IngestResult, message: str) -> None:
        result.failed += 1
        if len(result.errors) < _MAX_REPORTED_ERRORS:
            result.errors.append(message)

"""Celery worker: queued analysis runs and (optionally) scheduled AWS collection.

    celery -A app.worker worker --loglevel=INFO
    celery -A app.worker beat   --loglevel=INFO      # only if CLOUDSHIELD_SCHEDULE_COLLECT_MINUTES > 0
"""

import logging
from datetime import datetime, timedelta, timezone
from functools import lru_cache

from celery import Celery

from app.core.config import get_settings
from app.processing.normalizers.base import parse_timestamp

log = logging.getLogger(__name__)
settings = get_settings()

celery_app = Celery("cloudshield", broker=settings.celery_broker_url or "memory://")
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_ignore_result=True,
    timezone="UTC",
)
if settings.schedule_collect_minutes > 0:
    celery_app.conf.beat_schedule = {
        "collect-and-analyze": {"task": "cloudshield.collect_and_analyze",
                                "schedule": settings.schedule_collect_minutes * 60.0},
    }


@lru_cache
def _services():
    from app.database.session import create_engine_from_url, create_session_factory, init_db
    from app.evidence.store import build_evidence_store
    from app.services.analysis import AnalysisService
    from app.services.ingestion import IngestionService
    from app.services.models_registry import ModelRegistry

    engine = create_engine_from_url(settings.database_url)
    init_db(engine)
    session_factory = create_session_factory(engine)
    ingestion = IngestionService(session_factory, build_evidence_store(settings))
    return session_factory, ingestion, AnalysisService(session_factory, settings, ModelRegistry(settings))


@celery_app.task(name="cloudshield.analyze")
def analyze_task(run_id: str, start: str | None, end: str | None, actor: str) -> dict:
    _, _, analysis = _services()
    return analysis.run(parse_timestamp(start) if start else None, parse_timestamp(end) if end else None,
                        actor, run_id=run_id)


@celery_app.task(name="cloudshield.collect_and_analyze")
def collect_and_analyze() -> dict:
    from app.services.collection import collect

    session_factory, ingestion, analysis = _services()
    sources = ["cloudtrail", "guardduty", "cloudwatch"]
    if settings.vpc_flow_log_group:
        sources.append("vpc_flow")
    if settings.sqs_queue_url:
        sources.append("sqs")
    if settings.trail_bucket:
        sources.append("cloudtrail_s3")
    results = {}
    for source in sources:
        try:
            results[source] = collect(settings, session_factory, ingestion, source)
        except Exception as exc:  # one broken source must not stop the others
            log.exception("collection from %s failed", source)
            results[source] = {"error": str(exc)}
    since = datetime.now(timezone.utc) - timedelta(days=1)
    results["analysis"] = analysis.run(since, None, actor="scheduler")
    return results

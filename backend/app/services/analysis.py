"""Runs the analysis engine over stored events and persists detections, incidents and actions."""

import logging
import secrets
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select
from sqlalchemy.orm import Session, sessionmaker

from app.analysis.correlation import CorrelationConfig
from app.analysis.engine import AnalysisConfig, AnalysisEngine, Incident
from app.core.config import Settings
from app.database.models import (
    AnalysisRun,
    DetectionRecord,
    IncidentRecord,
    ResponseActionRecord,
    SecurityEventRecord,
    event_from_record,
    utcnow,
)
from app.processing.hashing import canonical_json, sha256_hex
from app.services.audit import audit
from app.services.models_registry import ModelRegistry
from app.services.inventory import load_inventory
from app.services.serialize import row_to_dict, utc

log = logging.getLogger(__name__)


def evidence_manifest(incident: Incident, events_by_id: dict, run_id: str, model_version: str) -> dict:
    manifest = {
        "incident_id": incident.incident_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "analysis_run_id": run_id,
        "model_version": model_version,
        "events": [
            {
                "event_id": eid,
                "source": events_by_id[eid].event_source.value,
                "source_event_id": events_by_id[eid].source_event_id,
                "timestamp": events_by_id[eid].timestamp.isoformat(),
                "raw_reference": events_by_id[eid].raw_event_reference,
                "raw_sha256": events_by_id[eid].raw_event_hash,
            }
            for eid in incident.event_ids
        ],
    }
    manifest["manifest_sha256"] = sha256_hex(canonical_json(manifest))
    return manifest


class AnalysisService:
    def __init__(self, session_factory: sessionmaker[Session], settings: Settings, registry: ModelRegistry):
        self.session_factory = session_factory
        self.settings = settings
        self.registry = registry

    def engine(self) -> AnalysisEngine:
        s = self.settings
        return AnalysisEngine(self.registry.get(), AnalysisConfig(
            window_minutes=s.window_minutes,
            attack_threshold=s.attack_probability_threshold,
            anomaly_threshold=s.anomaly_alert_threshold,
            correlation=CorrelationConfig(threshold=s.correlation_threshold),
        ))

    def _new_run(self, start, end, status: str) -> str:
        run_id = f"run_{datetime.now(timezone.utc):%Y%m%d%H%M%S}_{secrets.token_hex(3)}"
        with self.session_factory() as session:
            session.add(AnalysisRun(run_id=run_id, model_version=self.registry.get().version,
                                    range_start=start, range_end=end, status=status))
            session.commit()
        return run_id

    def submit(self, start: datetime | None = None, end: datetime | None = None, actor: str = "system") -> dict:
        """Queue on Celery when a broker is configured, otherwise run inline."""
        start, end = utc(start), utc(end)
        if not self.settings.celery_broker_url:
            return self.run(start, end, actor)
        from app.worker import analyze_task

        run_id = self._new_run(start, end, "queued")
        analyze_task.delay(run_id, start.isoformat() if start else None, end.isoformat() if end else None, actor)
        with self.session_factory() as session:
            return row_to_dict(session.get(AnalysisRun, run_id))

    def run(self, start: datetime | None = None, end: datetime | None = None, actor: str = "system",
            run_id: str | None = None) -> dict:
        start, end = utc(start), utc(end)
        engine = self.engine()
        run_id = run_id or self._new_run(start, end, "running")
        t0 = time.time()
        with self.session_factory() as session:
            run = session.get(AnalysisRun, run_id)
            run.status, run.started_at = "running", utcnow()
            session.commit()
            try:
                stmt = select(SecurityEventRecord).order_by(SecurityEventRecord.timestamp)
                if start:
                    stmt = stmt.where(SecurityEventRecord.timestamp >= start - timedelta(days=self.settings.history_lookback_days))
                if end:
                    stmt = stmt.where(SecurityEventRecord.timestamp < end)
                events = [event_from_record(r) for r in session.scalars(stmt)]
                score_from = start
                if score_from is None and events:
                    # Without an explicit range, treat the first day as baseline: no identity has any
                    # history yet, so scoring it would flag everyone as "new".
                    score_from = events[0].timestamp + timedelta(hours=self.settings.baseline_warmup_hours)
                inventory = load_inventory(session)
                result = engine.analyze(events, score_from=score_from, inventory=inventory)
                self._persist(session, run, result, {e.event_id: e for e in events}, start, end)
                run.status = "completed"
                run.n_events, run.n_windows = result.n_events, len(result.windows)
                run.n_detections, run.n_incidents = len(result.alerts), len(result.incidents)
                audit(session, actor, "analysis_run", "analysis_run", run_id,
                      detections=len(result.alerts), incidents=len(result.incidents))
            except Exception as exc:
                session.rollback()
                run = session.get(AnalysisRun, run_id)
                run.status, run.error = "failed", str(exc)[:2000]
                log.exception("analysis run %s failed", run_id)
            run.finished_at = utcnow()
            run.seconds = round(time.time() - t0, 2)
            session.commit()
            return row_to_dict(run)

    def _persist(self, session: Session, run: AnalysisRun, result, events_by_id: dict, start, end) -> None:
        # Replace previous machine output in scope, but never discard analyst decisions.
        det_filter = []
        inc_filter = []
        if start:
            det_filter.append(DetectionRecord.start >= start)
            inc_filter.append(IncidentRecord.start >= start)
        if end:
            det_filter.append(DetectionRecord.start < end)
            inc_filter.append(IncidentRecord.start < end)
        session.execute(delete(DetectionRecord).where(*det_filter))

        decided = set(session.scalars(
            select(ResponseActionRecord.incident_id).where(ResponseActionRecord.status != "proposed")))
        kept = set()
        for inc in session.scalars(select(IncidentRecord).where(*inc_filter)):
            if inc.status != "open" or inc.incident_id in decided or inc.analyst_notes:
                kept.add(inc.incident_id)
            else:
                session.execute(delete(ResponseActionRecord).where(ResponseActionRecord.incident_id == inc.incident_id))
                session.delete(inc)
        session.flush()

        version = run.model_version
        for incident in result.incidents:
            for alert in incident.alerts:
                session.merge(DetectionRecord(
                    detection_id=alert.alert_id, run_id=run.run_id, incident_id=incident.incident_id,
                    kind=alert.kind, rule=alert.rule, entity=alert.entity, start=alert.start, end=alert.end,
                    predicted_class=alert.predicted_class, class_probability=alert.class_probability,
                    attack_probability=alert.attack_probability, anomaly_score=alert.anomaly_score,
                    score=alert.score, probabilities=alert.probabilities,
                    explanation={**(alert.explanation or {}), "model_input": alert.model_input}
                    if alert.model_input else alert.explanation,
                    entities={"actors": sorted(alert.actors), "keys": sorted(alert.keys),
                              "ips": sorted(alert.ips), "resources": sorted(alert.resources)},
                    event_ids=alert.event_ids,
                ))
            fields = dict(
                run_id=run.run_id, title=incident.title, primary_class=incident.primary_class,
                risk_score=incident.risk["score"], risk_level=incident.risk["level"],
                start=incident.start, end=incident.end, alert_count=len(incident.alerts),
                event_count=len(incident.event_ids), correlation_score=incident.correlation_score,
                actors=incident.actors, source_ips=incident.source_ips, resources=incident.resources,
                access_keys=incident.access_keys, event_ids=incident.event_ids, links=incident.links,
                sequence=incident.sequence, risk=incident.risk, explanation=incident.explanation,
                graph=incident.graph, timeline=incident.timeline, mitre=incident.mitre,
                evidence_manifest=evidence_manifest(incident, events_by_id, run.run_id, version),
            )
            existing = session.get(IncidentRecord, incident.incident_id)
            if existing is not None:
                for key, value in fields.items():
                    setattr(existing, key, value)
            else:
                session.add(IncidentRecord(incident_id=incident.incident_id, **fields))
            for action in incident.recommendations:
                if session.get(ResponseActionRecord, action["action_id"]) is None:
                    session.add(ResponseActionRecord(
                        action_id=action["action_id"], incident_id=incident.incident_id,
                        action_type=action["action_type"], target=action["target"],
                        description=action["description"], rationale=action["rationale"],
                        api_call=action["api_call"], automatable=action["automatable"],
                        reversible=action["reversible"], evidence_event_ids=action["evidence_event_ids"]))
        log.info("run %s: %d detections, %d incidents (%d kept from earlier runs)",
                 run.run_id, len(result.alerts), len(result.incidents), len(kept))

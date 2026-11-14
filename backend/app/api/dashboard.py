import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_ingestion_service, get_registry, get_settings_dep
from app.core.config import Settings
from app.database.models import (
    AnalysisRun,
    DetectionRecord,
    IncidentRecord,
    ResponseActionRecord,
    SecurityEventRecord,
)
from app.services.ingestion import IngestionService
from app.services.models_registry import ModelRegistry, ModelsNotTrained
from app.services.serialize import utc
from app.services.simulation import seed_demo

router = APIRouter(prefix="/api", tags=["dashboard"])
DB = Annotated[Session, Depends(get_db)]
LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL"]
ACTIVE = ("open", "investigating")


@router.get("/dashboard/overview")
def overview(db: DB) -> dict:
    I = IncidentRecord
    total_events = db.scalar(select(func.count()).select_from(SecurityEventRecord)) or 0
    detections = db.scalar(select(func.count()).select_from(DetectionRecord)) or 0
    model_detections = db.scalar(select(func.count()).select_from(DetectionRecord).where(DetectionRecord.kind == "model")) or 0
    incidents = db.scalar(select(func.count()).select_from(I)) or 0
    active = db.scalar(select(func.count()).select_from(I).where(I.status.in_(ACTIVE))) or 0
    critical = db.scalar(select(func.count()).select_from(I).where(I.status.in_(ACTIVE), I.risk_level == "CRITICAL")) or 0
    high_or_critical = list(db.scalars(select(I).where(I.status.in_(ACTIVE), I.risk_level.in_(["HIGH", "CRITICAL"]))))
    resources_at_risk = sorted({r for inc in high_or_critical for r in inc.resources})
    pending = db.scalar(select(func.count()).select_from(ResponseActionRecord)
                        .where(ResponseActionRecord.status.in_(["proposed", "approved"]))) or 0
    last_run = db.scalar(select(AnalysisRun).order_by(AnalysisRun.started_at.desc()).limit(1))
    avg_risk = db.scalar(select(func.avg(I.risk_score)).where(I.status.in_(ACTIVE)))
    first, last = db.execute(select(func.min(SecurityEventRecord.timestamp), func.max(SecurityEventRecord.timestamp))).one()
    return {
        "total_events": total_events,
        "detections": detections,
        "model_detections": model_detections,
        "incidents": incidents,
        "active_incidents": active,
        "critical_incidents": critical,
        "alert_reduction": round(1 - incidents / detections, 4) if detections else None,
        "resources_at_risk": len(resources_at_risk),
        "resources_at_risk_list": resources_at_risk[:20],
        "pending_actions": pending,
        "average_active_risk": round(avg_risk, 1) if avg_risk is not None else None,
        "events_from": utc(first),
        "events_to": utc(last),
        "last_analysis": {"run_id": last_run.run_id, "status": last_run.status, "finished_at": utc(last_run.finished_at),
                          "seconds": last_run.seconds, "model_version": last_run.model_version} if last_run else None,
    }


@router.get("/dashboard/threat-trends")
def threat_trends(db: DB, bucket: Literal["hour", "day"] = "hour") -> list[dict]:
    fmt = "%Y-%m-%dT%H:00:00Z" if bucket == "hour" else "%Y-%m-%dT00:00:00Z"
    series: dict[str, dict] = defaultdict(lambda: {"events": 0, "detections": 0, "incidents": 0, "max_risk": 0.0})
    for (ts,) in db.execute(select(SecurityEventRecord.timestamp)):
        series[utc(ts).strftime(fmt)]["events"] += 1
    for (ts,) in db.execute(select(DetectionRecord.start)):
        series[utc(ts).strftime(fmt)]["detections"] += 1
    for ts, risk in db.execute(select(IncidentRecord.start, IncidentRecord.risk_score)):
        point = series[utc(ts).strftime(fmt)]
        point["incidents"] += 1
        point["max_risk"] = max(point["max_risk"], risk)
    return [{"time": k, **v} for k, v in sorted(series.items())]


@router.get("/dashboard/risk-distribution")
def risk_distribution(db: DB) -> dict:
    counts = dict(db.execute(select(IncidentRecord.risk_level, func.count()).group_by(IncidentRecord.risk_level)).all())
    by_class = dict(db.execute(select(IncidentRecord.primary_class, func.count()).group_by(IncidentRecord.primary_class)).all())
    by_status = dict(db.execute(select(IncidentRecord.status, func.count()).group_by(IncidentRecord.status)).all())
    return {"levels": [{"level": lvl, "count": counts.get(lvl, 0)} for lvl in LEVELS],
            "classes": [{"class": k, "count": v} for k, v in sorted(by_class.items(), key=lambda kv: -kv[1])],
            "statuses": [{"status": k, "count": v} for k, v in by_status.items()]}


@router.get("/dashboard/top-entities")
def top_entities(db: DB, limit: int = 10) -> dict:
    actors, ips, resources = Counter(), Counter(), Counter()
    for inc in db.scalars(select(IncidentRecord).where(IncidentRecord.risk_level.in_(["HIGH", "CRITICAL", "MEDIUM"]))):
        for a in inc.actors:
            actors[a] += inc.risk_score
        for ip in inc.source_ips:
            ips[ip] += inc.risk_score
        for r in inc.resources:
            resources[r] += inc.risk_score
    fmt = lambda c: [{"entity": k, "risk_sum": round(v, 1)} for k, v in c.most_common(limit)]  # noqa: E731
    return {"actors": fmt(actors), "ips": fmt(ips), "resources": fmt(resources)}


@router.get("/dashboard/layers")
def layer_activity(db: DB) -> list[dict]:
    rows = db.execute(select(SecurityEventRecord.layer, SecurityEventRecord.event_source, func.count())
                      .group_by(SecurityEventRecord.layer, SecurityEventRecord.event_source)).all()
    return [{"layer": layer, "source": source, "count": n} for layer, source, n in rows]


@router.get("/models")
def model_info(registry: Annotated[ModelRegistry, Depends(get_registry)]) -> dict:
    try:
        return registry.get().public_metadata()
    except ModelsNotTrained as exc:
        raise HTTPException(503, str(exc))


@router.get("/experiments")
def experiments(settings: Annotated[Settings, Depends(get_settings_dep)]) -> dict:
    path = Path(settings.reports_dir) / "experiments.json"
    if not path.exists():
        raise HTTPException(404, "No experiment report yet. Run `python -m app.cli experiments`.")
    return json.loads(path.read_text())


class SimulationRequest(BaseModel):
    seed: int = 2026
    days: int = 7
    attacks_per_day: float = 1.5


@router.post("/simulation/run")
def run_simulation(body: SimulationRequest,
                   settings: Annotated[Settings, Depends(get_settings_dep)],
                   ingestion: Annotated[IngestionService, Depends(get_ingestion_service)]) -> dict:
    if not settings.enable_simulation:
        raise HTTPException(403, "simulation is disabled (CLOUDSHIELD_ENABLE_SIMULATION=false)")
    if not 1 <= body.days <= 30 or not 0 <= body.attacks_per_day <= 10:
        raise HTTPException(422, "days must be 1-30 and attacks_per_day 0-10")
    return seed_demo(ingestion, settings.reports_dir, body.seed, body.days, body.attacks_per_day)

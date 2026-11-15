from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import get_analysis_service, get_db, get_settings_dep, require_role
from app.core.config import Settings
from app.services.auth import Principal
from app.database.models import AnalysisRun, DetectionRecord
from app.services.analysis import AnalysisService, flag_criteria
from app.services.serialize import row_to_dict

router = APIRouter(prefix="/api", tags=["analysis"])
DB = Annotated[Session, Depends(get_db)]


class RunRequest(BaseModel):
    start: datetime | None = None
    end: datetime | None = None


@router.post("/analysis/run")
def run_analysis(body: RunRequest, service: Annotated[AnalysisService, Depends(get_analysis_service)],
                 user: Annotated[Principal, Depends(require_role("analyst"))]) -> dict:
    return service.submit(body.start, body.end, actor=user.username)


@router.get("/analysis/runs")
def list_runs(db: DB, limit: Annotated[int, Query(ge=1, le=100)] = 20) -> list[dict]:
    rows = db.scalars(select(AnalysisRun).order_by(AnalysisRun.started_at.desc()).limit(limit))
    return [row_to_dict(r) for r in rows]


@router.get("/detections")
def list_detections(
    db: DB,
    settings: Annotated[Settings, Depends(get_settings_dep)],
    kind: str | None = None,
    predicted_class: str | None = None,
    incident_id: str | None = None,
    min_score: Annotated[float | None, Query(ge=0, le=1)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict:
    D = DetectionRecord
    filters = []
    if kind:
        filters.append(D.kind == kind)
    if predicted_class:
        filters.append(D.predicted_class == predicted_class)
    if incident_id:
        filters.append(D.incident_id == incident_id)
    if min_score is not None:
        filters.append(D.score >= min_score)
    total = db.scalar(select(func.count()).select_from(D).where(*filters)) or 0
    rows = db.scalars(select(D).where(*filters).order_by(D.start.desc()).limit(limit).offset(offset))
    return {"total": total, "items": [row_to_dict(r, exclude={"event_ids", "explanation"}) for r in rows],
            "flag_criteria": flag_criteria(settings)}


@router.get("/detections/{detection_id}")
def get_detection(detection_id: str, db: DB) -> dict:
    row = db.get(DetectionRecord, detection_id)
    if row is None:
        raise HTTPException(404, "detection not found")
    return row_to_dict(row)

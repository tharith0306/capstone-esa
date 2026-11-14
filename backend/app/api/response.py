from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_response_service, get_settings_dep
from app.core.config import Settings
from app.database.models import AuditLog, IncidentRecord, ResponseActionRecord
from app.services.response import ResponseService, WorkflowError
from app.services.serialize import row_to_dict

router = APIRouter(prefix="/api/response", tags=["response"])
DB = Annotated[Session, Depends(get_db)]
Service = Annotated[ResponseService, Depends(get_response_service)]


class Decision(BaseModel):
    analyst: str = Field(min_length=1, max_length=120)
    note: str | None = None


@router.get("/mode")
def response_mode(settings: Annotated[Settings, Depends(get_settings_dep)]) -> dict:
    return {"mode": settings.response_mode, "responder_profile_configured": bool(settings.responder_profile)}


@router.get("/actions")
def list_actions(db: DB, status: str | None = None, incident_id: str | None = None,
                 limit: Annotated[int, Query(ge=1, le=500)] = 200) -> list[dict]:
    A = ResponseActionRecord
    stmt = select(A, IncidentRecord.title, IncidentRecord.risk_level, IncidentRecord.risk_score).join(
        IncidentRecord, IncidentRecord.incident_id == A.incident_id)
    if status:
        stmt = stmt.where(A.status == status)
    if incident_id:
        stmt = stmt.where(A.incident_id == incident_id)
    stmt = stmt.order_by(IncidentRecord.risk_score.desc(), A.proposed_at).limit(limit)
    return [{**row_to_dict(a), "incident_title": t, "risk_level": lvl, "risk_score": score}
            for a, t, lvl, score in db.execute(stmt)]


def _call(fn, *args, **kwargs) -> dict:
    try:
        return fn(*args, **kwargs)
    except KeyError:
        raise HTTPException(404, "action not found")
    except WorkflowError as exc:
        raise HTTPException(409, str(exc))


@router.post("/actions/{action_id}/approve")
def approve(action_id: str, body: Decision, service: Service) -> dict:
    return _call(service.decide, action_id, body.analyst, True, body.note)


@router.post("/actions/{action_id}/reject")
def reject(action_id: str, body: Decision, service: Service) -> dict:
    return _call(service.decide, action_id, body.analyst, False, body.note)


@router.post("/actions/{action_id}/execute")
def execute(action_id: str, body: Decision, service: Service) -> dict:
    return _call(service.execute, action_id, body.analyst)


@router.post("/actions/{action_id}/rollback")
def rollback(action_id: str, body: Decision, service: Service) -> dict:
    return _call(service.execute, action_id, body.analyst, rollback=True)


@router.get("/audit")
def audit_log(db: DB, limit: Annotated[int, Query(ge=1, le=1000)] = 200) -> list[dict]:
    return [row_to_dict(a) for a in db.scalars(select(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit))]

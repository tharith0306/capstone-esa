from datetime import datetime, timezone
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_evidence_store, require_role
from app.services.auth import Principal
from app.database.models import (
    AuditLog,
    DetectionRecord,
    IncidentRecord,
    ResponseActionRecord,
    SecurityEventRecord,
    event_from_record,
)
from app.evidence.store import EvidenceStore
from app.schemas.event import EvidenceRef
from app.services.audit import audit
from app.services.serialize import row_to_dict

router = APIRouter(prefix="/api/incidents", tags=["incidents"])
DB = Annotated[Session, Depends(get_db)]

SUMMARY_EXCLUDE = {"event_ids", "links", "sequence", "graph", "timeline", "evidence_manifest", "explanation", "risk"}
Status = Literal["open", "investigating", "contained", "resolved", "false_positive"]


def _get(db: Session, incident_id: str) -> IncidentRecord:
    row = db.get(IncidentRecord, incident_id)
    if row is None:
        raise HTTPException(404, "incident not found")
    return row


@router.get("")
def list_incidents(
    db: DB,
    status: str | None = None,
    level: str | None = None,
    primary_class: str | None = None,
    min_risk: Annotated[float | None, Query(ge=0, le=100)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict:
    I = IncidentRecord
    filters = []
    if status:
        filters.append(I.status == status)
    if level:
        filters.append(I.risk_level == level.upper())
    if primary_class:
        filters.append(I.primary_class == primary_class)
    if min_risk is not None:
        filters.append(I.risk_score >= min_risk)
    total = db.scalar(select(func.count()).select_from(I).where(*filters)) or 0
    rows = db.scalars(select(I).where(*filters).order_by(I.risk_score.desc(), I.start.desc()).limit(limit).offset(offset))
    return {"total": total, "items": [row_to_dict(r, exclude=SUMMARY_EXCLUDE) for r in rows]}


@router.get("/{incident_id}")
def get_incident(incident_id: str, db: DB) -> dict:
    inc = row_to_dict(_get(db, incident_id))
    inc["detections"] = [row_to_dict(d, exclude={"event_ids"}) for d in db.scalars(
        select(DetectionRecord).where(DetectionRecord.incident_id == incident_id).order_by(DetectionRecord.start))]
    inc["actions"] = [row_to_dict(a) for a in db.scalars(
        select(ResponseActionRecord).where(ResponseActionRecord.incident_id == incident_id))]
    return inc


class IncidentUpdate(BaseModel):
    status: Status | None = None
    analyst_notes: str | None = None


@router.patch("/{incident_id}")
def update_incident(incident_id: str, body: IncidentUpdate, db: DB,
                    user: Annotated[Principal, Depends(require_role("analyst"))]) -> dict:
    inc = _get(db, incident_id)
    changes = {}
    if body.status and body.status != inc.status:
        changes["status"] = [inc.status, body.status]
        inc.status = body.status
    if body.analyst_notes is not None:
        inc.analyst_notes = body.analyst_notes
        changes["notes_updated"] = True
    if changes:
        audit(db, user.username, "update_incident", "incident", incident_id, **changes)
        db.commit()
    return row_to_dict(inc, exclude=SUMMARY_EXCLUDE)


@router.get("/{incident_id}/report")
def incident_report(incident_id: str, db: DB, store: Annotated[EvidenceStore, Depends(get_evidence_store)]) -> dict:
    """Forensic report: everything about the incident, with each raw record's hash re-verified."""
    inc = _get(db, incident_id)
    records = db.scalars(select(SecurityEventRecord).where(SecurityEventRecord.event_id.in_(inc.event_ids)))
    events = []
    verified_count = 0
    for rec in sorted(records, key=lambda r: r.timestamp):
        ev = event_from_record(rec)
        verified = store.verify(EvidenceRef(reference=ev.raw_event_reference, sha256=ev.raw_event_hash))
        verified_count += verified
        events.append({**ev.model_dump(mode="json"), "evidence_verified": verified})
    report = get_incident(incident_id, db)
    report["events"] = events
    report["evidence_summary"] = {"events": len(events), "verified": verified_count,
                                  "all_verified": verified_count == len(events)}
    report["audit_trail"] = [row_to_dict(a) for a in db.scalars(
        select(AuditLog).where(AuditLog.object_id.in_([incident_id, *[a["action_id"] for a in report["actions"]]]))
        .order_by(AuditLog.timestamp))]
    report["generated_at"] = datetime.now(timezone.utc).isoformat()
    return report

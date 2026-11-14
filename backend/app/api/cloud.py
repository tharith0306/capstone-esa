"""Cloud integration: inventory, accounts, telemetry health, collection triggers."""

from datetime import datetime, timezone
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_settings_dep, require_role
from app.core.config import Settings
from app.database.models import CloudResource, CollectorCheckpoint, SecurityEventRecord
from app.services.serialize import row_to_dict, utc

router = APIRouter(prefix="/api/cloud", tags=["cloud"])
DB = Annotated[Session, Depends(get_db)]


@router.get("/resources")
def resources(db: DB, resource_type: str | None = None, limit: Annotated[int, Query(ge=1, le=1000)] = 500) -> list[dict]:
    stmt = select(CloudResource).order_by(CloudResource.resource_type, CloudResource.resource_id).limit(limit)
    if resource_type:
        stmt = stmt.where(CloudResource.resource_type == resource_type)
    return [row_to_dict(r) for r in db.scalars(stmt)]


@router.get("/accounts")
def accounts(db: DB) -> list[dict]:
    rows = db.execute(select(SecurityEventRecord.cloud_provider, SecurityEventRecord.account_id, func.count(),
                             func.max(SecurityEventRecord.timestamp))
                      .group_by(SecurityEventRecord.cloud_provider, SecurityEventRecord.account_id)).all()
    return [{"cloud_provider": p, "account_id": a, "events": n, "last_event": utc(last)} for p, a, n, last in rows]


@router.get("/health")
def telemetry_health(db: DB) -> dict:
    now = datetime.now(timezone.utc)
    sources = []
    for source, n, last in db.execute(select(SecurityEventRecord.event_source, func.count(),
                                             func.max(SecurityEventRecord.timestamp))
                                      .group_by(SecurityEventRecord.event_source)):
        last = utc(last)
        sources.append({"source": source, "events": n, "last_event": last,
                        "lag_hours": round((now - last).total_seconds() / 3600, 1) if last else None})
    checkpoints = [{"collector": c.collector, "cursor": utc(c.cursor_time), "updated_at": utc(c.updated_at)}
                   for c in db.scalars(select(CollectorCheckpoint))]
    return {"sources": sources, "checkpoints": checkpoints,
            "inventory_resources": db.scalar(select(func.count()).select_from(CloudResource)) or 0}


@router.post("/inventory/refresh", dependencies=[Depends(require_role("admin"))])
def refresh_inventory(request: Request, settings: Annotated[Settings, Depends(get_settings_dep)]) -> dict:
    from app.services.inventory import refresh_inventory_from_aws

    try:
        return refresh_inventory_from_aws(settings, request.app.state.session_factory)
    except Exception as exc:  # botocore credential / permission errors
        raise HTTPException(502, f"AWS inventory scan failed: {exc}")


class CollectRequest(BaseModel):
    source: Literal["cloudtrail", "cloudtrail_s3", "vpc_flow", "guardduty", "cloudwatch", "sqs"]


@router.post("/collect", dependencies=[Depends(require_role("admin"))])
def collect_now(body: CollectRequest, request: Request, settings: Annotated[Settings, Depends(get_settings_dep)]) -> dict:
    from app.services.collection import collect

    try:
        return collect(settings, request.app.state.session_factory, request.app.state.ingestion, body.source)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except Exception as exc:
        raise HTTPException(502, f"collection from AWS failed: {exc}")

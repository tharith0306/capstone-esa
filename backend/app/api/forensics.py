"""Forensic investigation endpoints from the design: graph, timeline, evidence, LIME, counterfactuals,
PDF report and Neo4j export."""

from typing import Annotated

import pandas as pd
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import PlainTextResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_evidence_store, get_settings_dep, require_role
from app.api.incidents import incident_report
from app.core.config import Settings
from app.database.models import DetectionRecord, IncidentRecord
from app.evidence.store import EvidenceStore
from app.services.models_registry import ModelRegistry, ModelsNotTrained

router = APIRouter(prefix="/api/forensics", tags=["forensics"])
DB = Annotated[Session, Depends(get_db)]


def _incident(db: Session, incident_id: str) -> IncidentRecord:
    inc = db.get(IncidentRecord, incident_id)
    if inc is None:
        raise HTTPException(404, "incident not found")
    return inc


@router.get("/{incident_id}/graph")
def graph(incident_id: str, db: DB) -> dict:
    return _incident(db, incident_id).graph


@router.get("/{incident_id}/timeline")
def timeline(incident_id: str, db: DB) -> list[dict]:
    return _incident(db, incident_id).timeline


@router.get("/{incident_id}/evidence")
def evidence(incident_id: str, db: DB) -> dict:
    return _incident(db, incident_id).evidence_manifest


def _top_window(db: Session, incident_id: str) -> tuple[DetectionRecord, pd.Series]:
    _incident(db, incident_id)
    rows = db.scalars(select(DetectionRecord).where(DetectionRecord.incident_id == incident_id,
                                                    DetectionRecord.kind == "model")
                      .order_by(DetectionRecord.score.desc()))
    for det in rows:
        x = (det.explanation or {}).get("model_input")
        if x:
            return det, pd.Series(x)
    raise HTTPException(404, "this incident has no ML detection to explain (rule-only incident)")


def _local(request: Request):
    from app.ml.local_explain import LocalExplainer

    registry: ModelRegistry = request.app.state.registry
    try:
        bundle = registry.get()
    except ModelsNotTrained as exc:
        raise HTTPException(503, str(exc))
    cache = request.app.state.__dict__.setdefault("_local_explainers", {})
    if bundle.version not in cache:
        try:
            cache[bundle.version] = LocalExplainer(bundle)
        except ValueError as exc:
            raise HTTPException(409, str(exc))
    return cache[bundle.version], bundle


@router.get("/{incident_id}/lime")
def lime(incident_id: str, request: Request, db: DB) -> dict:
    det, x = _top_window(db, incident_id)
    local, bundle = _local(request)
    cls = bundle.classes.index(det.predicted_class) if det.predicted_class in bundle.classes else 1
    return {"detection_id": det.detection_id, **local.lime(x, cls)}


@router.get("/{incident_id}/counterfactual")
def counterfactual(incident_id: str, request: Request, db: DB) -> dict:
    det, x = _top_window(db, incident_id)
    local, _ = _local(request)
    return {"detection_id": det.detection_id, **local.counterfactuals(x)}


@router.get("/{incident_id}/report.pdf")
def report_pdf(incident_id: str, db: DB, store: Annotated[EvidenceStore, Depends(get_evidence_store)]) -> Response:
    from app.reports.pdf import build_incident_pdf

    pdf = build_incident_pdf(incident_report(incident_id, db, store))
    return Response(pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="cloudshield-{incident_id}.pdf"'})


@router.get("/{incident_id}/graph.cypher", response_class=PlainTextResponse)
def graph_cypher(incident_id: str, db: DB) -> str:
    from app.reports.neo4j_export import cypher_for_incident

    return cypher_for_incident(incident_id, _incident(db, incident_id).graph)


@router.post("/{incident_id}/neo4j", dependencies=[Depends(require_role("analyst"))])
def push_neo4j(incident_id: str, db: DB, settings: Annotated[Settings, Depends(get_settings_dep)]) -> dict:
    from app.reports.neo4j_export import push_to_neo4j

    if not settings.neo4j_uri:
        raise HTTPException(400, "Neo4j is not configured (CLOUDSHIELD_NEO4J_URI); download graph.cypher instead")
    try:
        return push_to_neo4j(settings, incident_id, _incident(db, incident_id).graph)
    except Exception as exc:
        raise HTTPException(502, f"Neo4j export failed: {exc}")

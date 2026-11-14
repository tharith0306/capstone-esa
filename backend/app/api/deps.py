from collections.abc import Iterator

from fastapi import HTTPException, Request
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.evidence.store import EvidenceStore
from app.services.analysis import AnalysisService
from app.services.ingestion import IngestionService
from app.services.models_registry import ModelRegistry
from app.services.response import ResponseService


def get_db(request: Request) -> Iterator[Session]:
    with request.app.state.session_factory() as session:
        yield session


def get_settings_dep(request: Request) -> Settings:
    return request.app.state.settings


def get_evidence_store(request: Request) -> EvidenceStore:
    return request.app.state.evidence_store


def get_ingestion_service(request: Request) -> IngestionService:
    return request.app.state.ingestion


def get_registry(request: Request) -> ModelRegistry:
    return request.app.state.registry


def get_analysis_service(request: Request) -> AnalysisService:
    registry: ModelRegistry = request.app.state.registry
    if not registry.available:
        raise HTTPException(503, "Models are not trained yet. Run `python -m app.cli train`.")
    return request.app.state.analysis


def get_response_service(request: Request) -> ResponseService:
    return request.app.state.response

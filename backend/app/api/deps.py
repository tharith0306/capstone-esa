from collections.abc import Iterator

from fastapi import Request
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.evidence.store import EvidenceStore
from app.services.ingestion import IngestionService


def get_db(request: Request) -> Iterator[Session]:
    with request.app.state.session_factory() as session:
        yield session


def get_settings_dep(request: Request) -> Settings:
    return request.app.state.settings


def get_evidence_store(request: Request) -> EvidenceStore:
    return request.app.state.evidence_store


def get_ingestion_service(request: Request) -> IngestionService:
    return request.app.state.ingestion

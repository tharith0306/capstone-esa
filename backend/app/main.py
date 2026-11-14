"""FastAPI entry point. Run with: uvicorn app.main:create_app --factory --reload"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api import events, health
from app.core.config import Settings, get_settings
from app.core.logging import configure_logging
from app.database.session import create_engine_from_url, create_session_factory, init_db
from app.evidence.store import build_evidence_store
from app.services.ingestion import IngestionService


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level)

    engine = create_engine_from_url(settings.database_url)
    init_db(engine)
    session_factory = create_session_factory(engine)
    evidence_store = build_evidence_store(settings)

    app = FastAPI(title="CloudShield API", version=__version__)
    app.state.settings = settings
    app.state.engine = engine
    app.state.session_factory = session_factory
    app.state.evidence_store = evidence_store
    app.state.ingestion = IngestionService(session_factory, evidence_store)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(health.router)
    app.include_router(events.router)
    return app

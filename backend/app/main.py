"""FastAPI entry point. Run with: uvicorn app.main:create_app --factory --reload"""

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api import analysis, auth, cloud, dashboard, events, forensics, health, incidents, response
from app.api.deps import current_user
from app.core.config import Settings, get_settings
from app.core.logging import configure_logging
from app.database.session import create_engine_from_url, create_session_factory, init_db
from app.evidence.store import build_evidence_store
from app.services.analysis import AnalysisService
from app.services.auth import AuthService
from app.services.ingestion import IngestionService
from app.services.models_registry import ModelRegistry
from app.services.response import ResponseService


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level)

    engine = create_engine_from_url(settings.database_url)
    init_db(engine)
    session_factory = create_session_factory(engine)
    evidence_store = build_evidence_store(settings)
    registry = ModelRegistry(settings)

    app = FastAPI(title="CloudShield API", version=__version__)
    app.state.settings = settings
    app.state.engine = engine
    app.state.session_factory = session_factory
    app.state.evidence_store = evidence_store
    app.state.registry = registry
    app.state.ingestion = IngestionService(session_factory, evidence_store)
    app.state.analysis = AnalysisService(session_factory, settings, registry)
    app.state.response = ResponseService(session_factory, settings)
    app.state.auth = AuthService(session_factory, settings)
    if settings.auth_enabled:
        app.state.auth.bootstrap_admin()

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(health.router)
    app.include_router(auth.router)
    for module in (events, analysis, incidents, forensics, response, dashboard, cloud):
        app.include_router(module.router, dependencies=[Depends(current_user)])
    return app

"""FastAPI application factory.

Run with: uvicorn --factory cybot.main:create_app
"""

from fastapi import APIRouter, Depends, FastAPI

from cybot import __version__
from cybot.api import alerts, health
from cybot.api.deps import Services, require_api_key
from cybot.config import Settings, get_settings
from cybot.ingestion.service import IngestionService
from cybot.storage import AlertRepository, Database


def build_services(settings: Settings) -> Services:
    db = Database(settings.database_url)
    db.create_all()
    repo = AlertRepository(db)
    return Services(settings=settings, repo=repo, ingestion=IngestionService(repo))


def create_app(settings: Settings | None = None, services: Services | None = None) -> FastAPI:
    settings = settings or get_settings()
    app = FastAPI(
        title=settings.app_name,
        version=__version__,
        description="Ingests and normalizes security alerts, then assesses risk with an "
        "agentic RAG workflow.",
    )
    app.state.services = services or build_services(settings)

    api = APIRouter(prefix="/api/v1", dependencies=[Depends(require_api_key)])
    api.include_router(alerts.router)

    app.include_router(health.router)
    app.include_router(api)
    return app

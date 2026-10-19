"""FastAPI application factory.

Run with: uvicorn --factory cybot.main:create_app
"""

import logging

from fastapi import APIRouter, Depends, FastAPI

from cybot import __version__
from cybot.agent import OllamaLLM, StructuredLLM, ThreatAnalyzer
from cybot.api import alerts, analysis, health, knowledge
from cybot.api.deps import Services, require_api_key
from cybot.config import Settings, get_settings
from cybot.ingestion.service import IngestionService
from cybot.rag import Embedder, KnowledgeBase, build_embedder
from cybot.storage import AlertRepository, Database

logger = logging.getLogger(__name__)


def build_services(
    settings: Settings,
    *,
    llm: StructuredLLM | None = None,
    embedder: Embedder | None = None,
) -> Services:
    db = Database(settings.database_url)
    db.create_all()
    repo = AlertRepository(db)

    kb = KnowledgeBase(
        embedder or build_embedder(settings),
        collection=settings.chroma_collection,
        persist_path=settings.chroma_path,
    )
    if settings.auto_index_knowledge and kb.count() == 0 and settings.knowledge_dir.is_dir():
        indexed = kb.index_directory(settings.knowledge_dir)
        logger.info("Indexed %d knowledge chunks from %s", indexed, settings.knowledge_dir)

    analyzer = ThreatAnalyzer(repo, kb, llm or OllamaLLM(settings), settings)
    return Services(
        settings=settings,
        repo=repo,
        ingestion=IngestionService(repo),
        knowledge=kb,
        analyzer=analyzer,
    )


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
    api.include_router(analysis.router)
    api.include_router(knowledge.router)

    app.include_router(health.router)
    app.include_router(api)
    return app

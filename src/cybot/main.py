"""FastAPI application factory.

Run with: uvicorn --factory cybot.main:create_app
"""

import logging

from fastapi import APIRouter, Depends, FastAPI

from cybot import __version__
from cybot.agent import OllamaLLM, StructuredLLM, ThreatAnalyzer
from cybot.agent.checkpoint import build_checkpointer
from cybot.api import actions, alerts, analysis, health, intel, knowledge
from cybot.api.deps import Services, require_api_key
from cybot.config import Settings, get_settings
from cybot.ingestion.service import IngestionService
from cybot.intel.providers import build_providers
from cybot.intel.service import ThreatIntelService
from cybot.rag import Embedder, KnowledgeBase, build_embedder
from cybot.response import ActionConnector, ResponsePlanner, ResponsePolicy, build_connector
from cybot.storage import AlertRepository, Database

logger = logging.getLogger(__name__)


def build_services(
    settings: Settings,
    *,
    llm: StructuredLLM | None = None,
    embedder: Embedder | None = None,
    connector: ActionConnector | None = None,
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

    intel = None
    if settings.intel_enabled and (providers := build_providers(settings)):
        intel = ThreatIntelService(providers, repo, cache_ttl_hours=settings.intel_cache_ttl_hours)
        logger.info("Threat intel providers: %s", ", ".join(intel.provider_names))

    llm = llm or OllamaLLM(settings)
    planner = None
    if settings.response_enabled:
        planner = ResponsePlanner(llm, ResponsePolicy.load(settings.response_policy_path))
        connector = connector or build_connector(settings)
        logger.info(
            "Response actions enabled (mode=%s, connector=%s)",
            settings.response_mode,
            connector.name,
        )

    analyzer = ThreatAnalyzer(
        repo,
        kb,
        llm,
        settings,
        intel,
        planner=planner,
        connector=connector,
        checkpointer=build_checkpointer(settings.checkpoint_path),
    )
    return Services(
        settings=settings,
        repo=repo,
        ingestion=IngestionService(repo),
        knowledge=kb,
        analyzer=analyzer,
        intel=intel,
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
    api.include_router(intel.router)
    api.include_router(actions.router)

    app.include_router(health.router)
    app.include_router(api)
    return app

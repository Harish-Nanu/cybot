from fastapi import APIRouter

from cybot.api.deps import ServicesDep
from cybot.api.schemas import KnowledgeHit, KnowledgeSearchRequest, KnowledgeStats

router = APIRouter(prefix="/knowledge", tags=["knowledge"])


@router.get("/stats", response_model=KnowledgeStats)
def stats(services: ServicesDep) -> KnowledgeStats:
    return KnowledgeStats.model_validate(services.knowledge.stats())


@router.post("/search", response_model=list[KnowledgeHit])
def search(request: KnowledgeSearchRequest, services: ServicesDep) -> list[KnowledgeHit]:
    hits = services.knowledge.search(request.query, k=request.k)
    return [
        KnowledgeHit(
            id=h.id, doc_id=h.doc_id, title=h.title, section=h.section, score=h.score, text=h.text
        )
        for h in hits
    ]


@router.post("/reindex", response_model=KnowledgeStats)
def reindex(services: ServicesDep) -> KnowledgeStats:
    """Rebuild the vector index from the markdown knowledge directory."""
    services.knowledge.index_directory(services.settings.knowledge_dir)
    return KnowledgeStats.model_validate(services.knowledge.stats())

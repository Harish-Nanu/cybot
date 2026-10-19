import logging
from typing import Annotated, Any

from fastapi import APIRouter, Body, HTTPException, Query, status

from cybot.api.alerts import get_alert_or_404
from cybot.api.deps import Services, ServicesDep
from cybot.api.schemas import AlertSummary, AnalysisResponse
from cybot.ingestion.normalizers import NORMALIZERS, UnknownSourceError
from cybot.models import AnalysisResult, NormalizedAlert

logger = logging.getLogger(__name__)

router = APIRouter(tags=["analysis"])


def run_analysis(services: Services, alert: NormalizedAlert) -> AnalysisResponse:
    analysis, trace = services.analyzer.analyze(alert)
    return AnalysisResponse(alert=AlertSummary.from_alert(alert), analysis=analysis, trace=trace)


def analyze_in_background(services: Services, alerts: list[NormalizedAlert]) -> None:
    for alert in alerts:
        try:
            services.analyzer.analyze(alert)
        except Exception:
            logger.exception("Background analysis failed for alert %s", alert.id)


@router.post("/alerts/{alert_id}/analyze", response_model=AnalysisResponse)
def analyze_alert(alert_id: str, services: ServicesDep) -> AnalysisResponse:
    """Run the agentic RAG workflow on a stored alert."""
    return run_analysis(services, get_alert_or_404(services, alert_id))


@router.get("/alerts/{alert_id}/analyses", response_model=list[AnalysisResult])
def list_alert_analyses(alert_id: str, services: ServicesDep) -> list[AnalysisResult]:
    get_alert_or_404(services, alert_id)
    return services.repo.list_analyses(alert_id)


@router.post("/analyze/{source}", response_model=AnalysisResponse)
def ingest_and_analyze(
    source: str, services: ServicesDep, payload: Annotated[dict[str, Any], Body()]
) -> AnalysisResponse:
    """Normalize, store and immediately analyze a single alert."""
    try:
        result = services.ingestion.ingest(source, payload)
    except UnknownSourceError:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            f"Unknown source '{source}'. Supported: {', '.join(NORMALIZERS)}",
        ) from None
    if result.errors:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, result.errors[0].error)
    if not result.alerts:
        raise HTTPException(status.HTTP_409_CONFLICT, "Alert was already ingested")
    return run_analysis(services, result.alerts[0])


@router.get("/analyses", response_model=list[AnalysisResult])
def triage_queue(
    services: ServicesDep,
    min_score: Annotated[int, Query(ge=0, le=100)] = 60,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
) -> list[AnalysisResult]:
    """Analyses at or above a risk score, highest first."""
    return services.repo.high_risk_analyses(min_score=min_score, limit=limit)

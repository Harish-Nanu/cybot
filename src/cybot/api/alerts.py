from typing import Annotated, Any

from fastapi import APIRouter, Body, HTTPException, Query, status

from cybot.api.deps import ServicesDep
from cybot.api.schemas import (
    AlertPage,
    AlertSummary,
    IngestErrorOut,
    IngestResponse,
    SourceInfo,
)
from cybot.ingestion.normalizers import NORMALIZERS, UnknownSourceError
from cybot.models import AlertCategory, NormalizedAlert, Severity

router = APIRouter(tags=["alerts"])


@router.get("/sources", response_model=list[SourceInfo])
def list_sources() -> list[SourceInfo]:
    return [SourceInfo(source=n.source, description=n.description) for n in NORMALIZERS.values()]


@router.post("/ingest/{source}", response_model=IngestResponse, status_code=status.HTTP_201_CREATED)
def ingest_alerts(
    source: str,
    services: ServicesDep,
    payload: Annotated[dict[str, Any] | list[dict[str, Any]], Body()],
) -> IngestResponse:
    """Ingest one alert object or a JSON array of alerts in the source's native format."""
    try:
        result = services.ingestion.ingest(source, payload)
    except UnknownSourceError:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            f"Unknown source '{source}'. Supported: {', '.join(NORMALIZERS)}",
        ) from None
    if result.received and not result.alerts and not result.duplicates:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            {
                "message": "No alerts could be normalized",
                "errors": [e.__dict__ for e in result.errors],
            },
        )
    return IngestResponse(
        source=result.source,
        received=result.received,
        ingested=len(result.alerts),
        duplicates=result.duplicates,
        alerts=[AlertSummary.from_alert(a) for a in result.alerts],
        errors=[IngestErrorOut(index=e.index, error=e.error) for e in result.errors],
    )


@router.get("/alerts", response_model=AlertPage)
def list_alerts(
    services: ServicesDep,
    source: str | None = None,
    min_severity: Severity | None = None,
    category: AlertCategory | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> AlertPage:
    alerts, total = services.repo.list_alerts(
        source=source, min_severity=min_severity, category=category, limit=limit, offset=offset
    )
    return AlertPage(
        total=total, limit=limit, offset=offset, items=[AlertSummary.from_alert(a) for a in alerts]
    )


def _get_alert_or_404(services: ServicesDep, alert_id: str) -> NormalizedAlert:
    alert = services.repo.get_alert(alert_id)
    if alert is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found")
    return alert


@router.get("/alerts/{alert_id}", response_model=NormalizedAlert)
def get_alert(alert_id: str, services: ServicesDep) -> NormalizedAlert:
    return _get_alert_or_404(services, alert_id)


@router.get("/alerts/{alert_id}/related", response_model=list[AlertSummary])
def related_alerts(
    alert_id: str,
    services: ServicesDep,
    window_hours: Annotated[int | None, Query(ge=1, le=24 * 30)] = None,
) -> list[AlertSummary]:
    alert = _get_alert_or_404(services, alert_id)
    window = window_hours or services.settings.correlation_window_hours
    return [
        AlertSummary.from_alert(a) for a in services.repo.find_related(alert, window_hours=window)
    ]

from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from cybot.api.alerts import get_alert_or_404
from cybot.api.deps import Services, ServicesDep
from cybot.ingestion.extract import detect_indicator_type
from cybot.intel.service import ThreatIntelService
from cybot.models import Indicator, IndicatorIntel, IndicatorType

router = APIRouter(tags=["threat-intel"])


class IntelProviders(BaseModel):
    enabled: bool
    providers: list[str]


class IntelLookupRequest(BaseModel):
    value: str = Field(min_length=1, max_length=2048)
    type: IndicatorType | None = Field(default=None, description="Auto-detected when omitted")


def _intel_or_503(services: Services) -> ThreatIntelService:
    if services.intel is None:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "Threat intelligence is disabled or no providers are configured",
        )
    return services.intel


@router.get("/intel/providers", response_model=IntelProviders)
def providers(services: ServicesDep) -> IntelProviders:
    names = services.intel.provider_names if services.intel else []
    return IntelProviders(enabled=bool(names), providers=names)


@router.post("/intel/lookup", response_model=IndicatorIntel)
def lookup(request: IntelLookupRequest, services: ServicesDep) -> IndicatorIntel:
    """Reputation lookup of a single indicator across all applicable providers."""
    intel = _intel_or_503(services)
    value = request.value.strip()
    itype = request.type or detect_indicator_type(value)
    if itype is None:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "Could not detect the indicator type; pass 'type' explicitly",
        )
    return intel.lookup(Indicator(type=itype, value=value))


@router.post("/alerts/{alert_id}/enrich", response_model=list[IndicatorIntel])
def enrich_alert(
    alert_id: str,
    services: ServicesDep,
    limit: Annotated[int | None, Query(ge=1, le=50)] = None,
) -> list[IndicatorIntel]:
    """Look up a stored alert's own indicators (most specific first)."""
    intel = _intel_or_503(services)
    alert = get_alert_or_404(services, alert_id)
    candidates = intel.candidates(alert.indicators)
    return intel.enrich(candidates[: limit or services.settings.intel_max_lookups])

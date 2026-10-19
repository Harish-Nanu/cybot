"""FastAPI dependencies: shared services and API-key auth."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader

from cybot.agent import ThreatAnalyzer
from cybot.config import Settings
from cybot.ingestion.service import IngestionService
from cybot.intel.service import ThreatIntelService
from cybot.rag import KnowledgeBase
from cybot.storage import AlertRepository


@dataclass
class Services:
    settings: Settings
    repo: AlertRepository
    ingestion: IngestionService
    knowledge: KnowledgeBase
    analyzer: ThreatAnalyzer
    intel: ThreatIntelService | None = None


def get_services(request: Request) -> Services:
    return request.app.state.services


ServicesDep = Annotated[Services, Depends(get_services)]

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def require_api_key(
    services: ServicesDep, api_key: Annotated[str | None, Security(_api_key_header)]
) -> None:
    expected = services.settings.api_key
    if not expected:
        return
    if not api_key or not secrets.compare_digest(api_key, expected):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or missing API key")

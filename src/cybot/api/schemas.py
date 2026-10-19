"""Request/response models specific to the HTTP API."""

from datetime import datetime

from pydantic import BaseModel

from cybot.models import AlertCategory, NormalizedAlert, Severity


class AlertSummary(BaseModel):
    id: str
    source: str
    title: str
    severity: Severity
    category: AlertCategory
    timestamp: datetime
    src_ip: str | None = None
    dst_ip: str | None = None
    hostname: str | None = None
    username: str | None = None

    @classmethod
    def from_alert(cls, alert: NormalizedAlert) -> "AlertSummary":
        return cls.model_validate(alert.model_dump(include=set(cls.model_fields)))


class AlertPage(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[AlertSummary]


class SourceInfo(BaseModel):
    source: str
    description: str


class IngestErrorOut(BaseModel):
    index: int
    error: str


class IngestResponse(BaseModel):
    source: str
    received: int
    ingested: int
    duplicates: int
    alerts: list[AlertSummary]
    errors: list[IngestErrorOut]

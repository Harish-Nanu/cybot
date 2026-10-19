"""Request/response models specific to the HTTP API."""

from datetime import datetime

from pydantic import BaseModel, Field

from cybot.models import AlertCategory, AnalysisResult, NormalizedAlert, Severity


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


class AnalysisResponse(BaseModel):
    alert: AlertSummary
    analysis: AnalysisResult
    trace: list[str]


class KnowledgeSearchRequest(BaseModel):
    query: str = Field(min_length=1, max_length=2000)
    k: int = Field(default=4, ge=1, le=20)


class KnowledgeHit(BaseModel):
    id: str
    doc_id: str
    title: str
    section: str
    score: float
    text: str


class KnowledgeStats(BaseModel):
    collection: str
    embedder: str
    chunks: int
    documents: int

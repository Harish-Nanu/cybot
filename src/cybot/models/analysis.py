"""Output schema of the threat-analysis agent."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from cybot.models.alert import Severity


class ResponsePhase(StrEnum):
    INVESTIGATION = "investigation"
    CONTAINMENT = "containment"
    ERADICATION = "eradication"
    RECOVERY = "recovery"
    PREVENTION = "prevention"


class Priority(StrEnum):
    IMMEDIATE = "immediate"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Likelihood(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class RiskAssessment(BaseModel):
    risk_score: int = Field(ge=0, le=100, description="0 (benign) to 100 (active compromise)")
    risk_level: Severity
    summary: str = Field(description="One or two sentence executive summary")
    rationale: str = Field(description="Why this score: evidence, context, and correlations")
    mitre_techniques: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    false_positive_likelihood: Likelihood = Likelihood.MEDIUM


class Recommendation(BaseModel):
    action: str
    phase: ResponsePhase
    priority: Priority
    rationale: str = ""


class KnowledgeReference(BaseModel):
    doc_id: str
    title: str
    source: str
    score: float | None = None


class AnalysisResult(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    alert_id: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    assessment: RiskAssessment
    recommendations: list[Recommendation] = Field(default_factory=list)
    related_alert_ids: list[str] = Field(default_factory=list)
    references: list[KnowledgeReference] = Field(default_factory=list)
    model: str | None = None
    retrieval_attempts: int = 0
    duration_ms: int | None = None

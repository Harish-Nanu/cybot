"""Threat-intelligence lookup results."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from cybot.models.alert import Indicator, IndicatorType


class Verdict(StrEnum):
    UNKNOWN = "unknown"
    HARMLESS = "harmless"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class IntelResult(BaseModel):
    """One provider's opinion about one indicator."""

    provider: str
    indicator_type: IndicatorType
    value: str
    verdict: Verdict = Verdict.UNKNOWN
    score: int = Field(default=0, ge=0, le=100, description="Normalized maliciousness, 0-100")
    summary: str = ""
    tags: list[str] = Field(default_factory=list)
    reference: str | None = None
    fetched_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    cached: bool = False
    error: str | None = None


# Precedence when providers disagree: any malicious report wins, then suspicious;
# an explicit "harmless" is more informative than "unknown".
_PRECEDENCE = [Verdict.MALICIOUS, Verdict.SUSPICIOUS, Verdict.HARMLESS, Verdict.UNKNOWN]


class IndicatorIntel(BaseModel):
    """All provider results for one indicator, with a combined verdict."""

    indicator: Indicator
    verdict: Verdict = Verdict.UNKNOWN
    score: int = 0
    results: list[IntelResult] = Field(default_factory=list)

    @classmethod
    def aggregate(cls, indicator: Indicator, results: list[IntelResult]) -> IndicatorIntel:
        usable = [r for r in results if r.error is None]
        verdicts = {r.verdict for r in usable}
        verdict = next((v for v in _PRECEDENCE if v in verdicts), Verdict.UNKNOWN)
        score = max((r.score for r in usable), default=0)
        return cls(indicator=indicator, verdict=verdict, score=score, results=results)

    def describe(self) -> str:
        """One line per indicator for prompts and reports."""
        parts = [
            f"{r.provider}: {r.verdict}" + (f" ({r.summary})" if r.summary else "")
            for r in self.results
            if r.error is None
        ]
        errors = [r.provider for r in self.results if r.error]
        if errors:
            parts.append(f"lookup failed: {', '.join(errors)}")
        return (
            f"{self.indicator.type}:{self.indicator.value} -> {self.verdict.upper()} "
            f"(score {self.score}) | " + "; ".join(parts)
        )

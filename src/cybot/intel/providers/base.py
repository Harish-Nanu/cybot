from __future__ import annotations

import logging
from abc import ABC, abstractmethod

import httpx

from cybot.ingestion.extract import is_valid_ip
from cybot.models.alert import Indicator, IndicatorType
from cybot.models.intel import IntelResult, Verdict

logger = logging.getLogger(__name__)


def is_public_ip(value: str) -> bool:
    import ipaddress

    return is_valid_ip(value) and ipaddress.ip_address(value).is_global


class IntelProvider(ABC):
    """A threat-intelligence source that can give a verdict on some indicator types."""

    name: str
    supported_types: frozenset[IndicatorType]
    # Remote reputation services know nothing about private/reserved addresses.
    requires_public_ip: bool = True
    cacheable: bool = True

    def supports(self, indicator: Indicator) -> bool:
        if indicator.type not in self.supported_types:
            return False
        if indicator.type == IndicatorType.IP and self.requires_public_ip:
            return is_public_ip(indicator.value)
        return True

    def lookup(self, indicator: Indicator) -> IntelResult:
        """Never raises: failures are reported in ``IntelResult.error``."""
        try:
            return self._lookup(indicator)
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            reason = "rate limited" if status == 429 else f"HTTP {status}"
            return self._error(indicator, reason)
        except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
            logger.warning("%s lookup failed for %s: %s", self.name, indicator.value, exc)
            return self._error(indicator, f"{type(exc).__name__}: {exc}")

    @abstractmethod
    def _lookup(self, indicator: Indicator) -> IntelResult: ...

    def _result(
        self,
        indicator: Indicator,
        verdict: Verdict,
        score: int = 0,
        summary: str = "",
        tags: list[str] | None = None,
        reference: str | None = None,
    ) -> IntelResult:
        return IntelResult(
            provider=self.name,
            indicator_type=indicator.type,
            value=indicator.value,
            verdict=verdict,
            score=max(0, min(100, int(score))),
            summary=summary,
            tags=tags or [],
            reference=reference,
        )

    def _error(self, indicator: Indicator, message: str) -> IntelResult:
        return IntelResult(
            provider=self.name, indicator_type=indicator.type, value=indicator.value, error=message
        )

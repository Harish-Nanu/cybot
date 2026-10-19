from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping
from typing import Any

from cybot.ingestion.extract import dedupe_indicators, extract_indicators, is_valid_ip
from cybot.models.alert import Indicator, IndicatorType, NormalizedAlert


class NormalizationError(ValueError):
    """Raised when a payload cannot be mapped to the common alert schema."""


class Normalizer(ABC):
    """Maps one vendor's alert payload onto :class:`NormalizedAlert`."""

    source: str
    description: str = ""

    def normalize(self, payload: Mapping[str, Any]) -> NormalizedAlert:
        if not isinstance(payload, Mapping):
            raise NormalizationError(f"{self.source}: payload must be a JSON object")
        alert = self._normalize(payload)
        alert.indicators = self._collect_indicators(alert)
        return alert

    @abstractmethod
    def _normalize(self, payload: Mapping[str, Any]) -> NormalizedAlert: ...

    def _collect_indicators(self, alert: NormalizedAlert) -> list[Indicator]:
        """Merge vendor-provided IOCs with structured fields and IOCs found in free text."""
        structured: list[Indicator] = []
        for ip in (alert.src_ip, alert.dst_ip):
            if is_valid_ip(ip):
                structured.append(Indicator(type=IndicatorType.IP, value=ip))
        if alert.hostname:
            structured.append(Indicator(type=IndicatorType.HOST, value=alert.hostname))
        if alert.username:
            structured.append(Indicator(type=IndicatorType.USER, value=alert.username))
        from_text = extract_indicators([alert.title, alert.description])
        return dedupe_indicators([*alert.indicators, *structured, *from_text])

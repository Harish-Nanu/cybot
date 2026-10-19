"""Ingestion pipeline: normalize vendor payloads, drop duplicates, persist."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from cybot.ingestion.normalizers import NormalizationError, get_normalizer
from cybot.models import NormalizedAlert
from cybot.storage import AlertRepository


@dataclass
class IngestError:
    index: int
    error: str


@dataclass
class IngestResult:
    source: str
    received: int
    alerts: list[NormalizedAlert] = field(default_factory=list)
    duplicates: int = 0
    errors: list[IngestError] = field(default_factory=list)


class IngestionService:
    def __init__(self, repo: AlertRepository) -> None:
        self.repo = repo

    def ingest(
        self, source: str, payloads: Mapping[str, Any] | Sequence[Mapping[str, Any]]
    ) -> IngestResult:
        """Normalize and store payloads. Raises UnknownSourceError for unsupported sources."""
        normalizer = get_normalizer(source)
        items = [payloads] if isinstance(payloads, Mapping) else list(payloads)
        result = IngestResult(source=normalizer.source, received=len(items))

        normalized: list[NormalizedAlert] = []
        for index, payload in enumerate(items):
            try:
                normalized.append(normalizer.normalize(payload))
            except (NormalizationError, ValueError, TypeError) as exc:
                result.errors.append(IngestError(index=index, error=str(exc)))

        # Webhook senders retry; skip events we've already stored (and repeats within the batch).
        seen = self.repo.existing_source_ids(
            normalizer.source, (a.source_alert_id for a in normalized if a.source_alert_id)
        )
        for alert in normalized:
            if alert.source_alert_id and alert.source_alert_id in seen:
                result.duplicates += 1
                continue
            if alert.source_alert_id:
                seen.add(alert.source_alert_id)
            result.alerts.append(alert)

        self.repo.add_alerts(result.alerts)
        return result

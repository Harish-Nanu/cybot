"""Fan indicator lookups out to providers, with caching and a per-call budget."""

from __future__ import annotations

from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from typing import TYPE_CHECKING

from cybot.ingestion.extract import dedupe_indicators
from cybot.intel.models import IndicatorIntel, IntelResult
from cybot.intel.providers import IntelProvider, is_public_ip
from cybot.models.alert import Indicator, IndicatorType

if TYPE_CHECKING:  # storage imports intel.models; avoid a runtime cycle
    from cybot.storage import AlertRepository

IT = IndicatorType

# File hashes and URLs are the most specific evidence; private IPs the least.
_TYPE_PRIORITY = {
    IT.SHA256: 0,
    IT.SHA1: 0,
    IT.MD5: 0,
    IT.URL: 1,
    IT.DOMAIN: 2,
    IT.EMAIL: 3,
    IT.IP: 4,
}


def priority(indicator: Indicator) -> int:
    rank = _TYPE_PRIORITY.get(indicator.type, 9)
    if indicator.type == IT.IP and not is_public_ip(indicator.value):
        rank += 1
    return rank


class ThreatIntelService:
    def __init__(
        self,
        providers: list[IntelProvider],
        repo: AlertRepository | None = None,
        *,
        cache_ttl_hours: int = 24,
        max_workers: int = 8,
    ) -> None:
        self.providers = providers
        self.repo = repo
        self.cache_ttl = timedelta(hours=cache_ttl_hours)
        self.max_workers = max_workers

    @property
    def provider_names(self) -> list[str]:
        return [p.name for p in self.providers]

    def candidates(self, indicators: Iterable[Indicator]) -> list[Indicator]:
        """Unique indicators that at least one provider can look up, most specific first."""
        supported = [
            i for i in dedupe_indicators(indicators) if any(p.supports(i) for p in self.providers)
        ]
        return sorted(supported, key=priority)

    def enrich(self, indicators: Iterable[Indicator]) -> list[IndicatorIntel]:
        """Look up each indicator with every provider that supports it (input order kept)."""
        indicators = dedupe_indicators(indicators)
        results: dict[tuple[int, str], IntelResult] = {}
        pending: list[tuple[int, IntelProvider, Indicator]] = []

        for idx, indicator in enumerate(indicators):
            for provider in self.providers:
                if not provider.supports(indicator):
                    continue
                cached = self._from_cache(provider, indicator)
                if cached is not None:
                    results[(idx, provider.name)] = cached
                else:
                    pending.append((idx, provider, indicator))

        if pending:
            with ThreadPoolExecutor(max_workers=min(self.max_workers, len(pending))) as pool:
                fetched = list(pool.map(lambda job: job[1].lookup(job[2]), pending))
            for (idx, provider, _), result in zip(pending, fetched, strict=True):
                results[(idx, provider.name)] = result
                if provider.cacheable and result.error is None and self.repo is not None:
                    self.repo.put_cached_intel(result)

        return [
            IndicatorIntel.aggregate(
                indicator,
                [results[(idx, p.name)] for p in self.providers if (idx, p.name) in results],
            )
            for idx, indicator in enumerate(indicators)
        ]

    def lookup(self, indicator: Indicator) -> IndicatorIntel:
        return self.enrich([indicator])[0]

    def _from_cache(self, provider: IntelProvider, indicator: Indicator) -> IntelResult | None:
        if not provider.cacheable or self.repo is None:
            return None
        return self.repo.get_cached_intel(
            provider.name, indicator.type.value, indicator.value, max_age=self.cache_ttl
        )

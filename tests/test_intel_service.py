from datetime import UTC, datetime, timedelta

from cybot.intel import IntelResult, Verdict
from cybot.intel.providers import IntelProvider, LocalIntelProvider
from cybot.intel.service import ThreatIntelService
from cybot.models import Indicator, IndicatorType
from tests.conftest import INTEL_FILE

IT = IndicatorType


class CountingProvider(IntelProvider):
    name = "counting"
    supported_types = frozenset({IT.IP, IT.SHA256, IT.DOMAIN})

    def __init__(self, verdict=Verdict.MALICIOUS, error=None):
        self.verdict, self.error, self.calls = verdict, error, []

    def _lookup(self, indicator):
        self.calls.append(indicator.value)
        if self.error:
            return self._error(indicator, self.error)
        return self._result(indicator, self.verdict, 70, summary="seen")


PUBLIC_IP = Indicator(type=IT.IP, value="8.8.8.8")
PRIVATE_IP = Indicator(type=IT.IP, value="10.0.0.1")
HASH = Indicator(type=IT.SHA256, value="a" * 64)
USER = Indicator(type=IT.USER, value="j.doe")


def test_enrich_combines_providers_and_keeps_order(repo):
    counting = CountingProvider()
    service = ThreatIntelService([LocalIntelProvider(INTEL_FILE), counting], repo)
    bad_ip = Indicator(type=IT.IP, value="203.0.113.45")
    out = service.enrich([PUBLIC_IP, bad_ip, PUBLIC_IP])

    assert [i.indicator.value for i in out] == ["8.8.8.8", "203.0.113.45"]
    assert [r.provider for r in out[0].results] == ["local", "counting"]
    # Remote provider skipped the documentation-range IP; local intel still flags it.
    assert [r.provider for r in out[1].results] == ["local"]
    assert out[1].verdict == Verdict.MALICIOUS
    assert counting.calls == ["8.8.8.8"]


def test_results_are_cached(repo):
    counting = CountingProvider()
    service = ThreatIntelService([counting], repo)
    first = service.lookup(PUBLIC_IP)
    second = service.lookup(PUBLIC_IP)
    assert counting.calls == ["8.8.8.8"]
    assert not first.results[0].cached and second.results[0].cached
    assert second.verdict == Verdict.MALICIOUS


def test_errors_are_not_cached(repo):
    failing = CountingProvider(error="rate limited")
    service = ThreatIntelService([failing], repo)
    service.lookup(PUBLIC_IP)
    result = service.lookup(PUBLIC_IP)
    assert failing.calls == ["8.8.8.8", "8.8.8.8"]
    assert result.results[0].error == "rate limited"
    assert result.verdict == Verdict.UNKNOWN


def test_cache_expires(repo):
    counting = CountingProvider()
    repo.put_cached_intel(
        IntelResult(
            provider="counting",
            indicator_type=IT.IP,
            value="8.8.8.8",
            verdict=Verdict.HARMLESS,
            fetched_at=datetime.now(UTC) - timedelta(hours=48),
        )
    )
    result = ThreatIntelService([counting], repo, cache_ttl_hours=24).lookup(PUBLIC_IP)
    assert counting.calls == ["8.8.8.8"]
    assert result.verdict == Verdict.MALICIOUS


def test_works_without_repository():
    counting = CountingProvider()
    service = ThreatIntelService([counting])
    service.lookup(PUBLIC_IP)
    service.lookup(PUBLIC_IP)
    assert len(counting.calls) == 2


def test_candidates_filter_and_prioritize():
    service = ThreatIntelService([LocalIntelProvider(INTEL_FILE)])
    candidates = service.candidates([PRIVATE_IP, USER, PUBLIC_IP, HASH, PUBLIC_IP])
    assert candidates == [HASH, PUBLIC_IP, PRIVATE_IP]


def test_unsupported_indicator_yields_empty_unknown(repo):
    out = ThreatIntelService([CountingProvider()], repo).lookup(USER)
    assert out.results == [] and out.verdict == Verdict.UNKNOWN

import re

import pytest

from cybot.agent import ThreatAnalyzer
from cybot.agent.heuristics import baseline_score, fallback_recommendations
from cybot.agent.prompts import IndicatorSelection
from cybot.config import Settings
from cybot.intel.providers import IntelProvider, LocalIntelProvider
from cybot.intel.service import ThreatIntelService
from cybot.models import (
    Indicator,
    IndicatorIntel,
    IndicatorType,
    ResponsePhase,
    Severity,
    Verdict,
)
from tests.conftest import INTEL_FILE, FakeLLM

IT = IndicatorType


def credential_dumping(alerts):
    return next(a for a in alerts if a.title == "Credential Dumping")


@pytest.fixture
def make_analyzer(repo, knowledge_base, sample_alerts):
    repo.add_alerts(sample_alerts)

    def _make(llm, providers=None, max_lookups=8):
        providers = [LocalIntelProvider(INTEL_FILE)] if providers is None else providers
        intel = ThreatIntelService(providers, repo)
        settings = Settings(intel_max_lookups=max_lookups)
        return ThreatAnalyzer(repo, knowledge_base, llm, settings, intel)

    return _make


def llm_down(**responses):
    return FakeLLM(responses, default_error=ConnectionError("down"))


def test_enrichment_within_budget_skips_llm_selection(make_analyzer, sample_alerts):
    llm = llm_down()
    result, trace = make_analyzer(llm, max_lookups=25).analyze(credential_dumping(sample_alerts))

    assert trace[1].startswith("select_indicators: all")
    assert trace[2].startswith("enrich_indicators")
    assert not llm.called("IndicatorSelection")
    verdicts = {i.indicator.value: i.verdict for i in result.intel}
    # The alert's own hash plus C2 infrastructure from the correlated beacon/exfil alerts.
    assert (
        verdicts["92804faaab2175dc501d73e814663058c78c0a042675a8937266357bcfb96c50"] == "malicious"
    )
    assert verdicts["update-cdn-sync.net"] == "malicious"
    assert verdicts["198.51.100.77"] == "malicious"
    # The alert's own indicators are looked up first.
    assert result.intel[0].indicator.type == IT.SHA256


def test_llm_selects_indicators_when_over_budget(make_analyzer, sample_alerts):
    llm = llm_down(IndicatorSelection=IndicatorSelection(selected=[3, 3, 1, 99]))
    result, trace = make_analyzer(llm, max_lookups=2).analyze(credential_dumping(sample_alerts))

    (prompt,) = llm.called("IndicatorSelection")
    assert "at most 2 threat-intelligence" in prompt
    assert len(result.intel) == 2
    assert "LLM chose 2/" in trace[1]
    candidates = [line for line in prompt.splitlines() if re.match(r"\[\d+\] ", line)]
    assert candidates[2].endswith(result.intel[0].indicator.value)
    assert candidates[0].endswith(result.intel[1].indicator.value)


def test_selection_falls_back_to_priority_order(make_analyzer, sample_alerts):
    result, trace = make_analyzer(llm_down(), max_lookups=1).analyze(
        credential_dumping(sample_alerts)
    )
    assert "LLM failed, top 1/" in trace[1]
    assert [i.indicator.type for i in result.intel] == [IT.SHA256]


def test_intel_raises_heuristic_score_and_drives_fallback_actions(make_analyzer, sample_alerts):
    alert = next(a for a in sample_alerts if a.source == "splunk")  # exfil, severity high
    result, _ = make_analyzer(llm_down()).analyze(alert)

    assert any(i.verdict == Verdict.MALICIOUS for i in result.intel)
    assert "Threat intel marks as malicious" in result.assessment.rationale
    first = result.recommendations[0]
    assert first.phase == ResponsePhase.CONTAINMENT
    assert first.action.startswith("Block known-malicious indicators")
    assert "198.51.100.77" in first.action


def test_intel_appears_in_assessment_prompt(make_analyzer, sample_alerts):
    llm = llm_down()
    make_analyzer(llm).analyze(credential_dumping(sample_alerts))
    (prompt,) = llm.called("RiskAssessment")
    assert "THREAT INTELLIGENCE:" in prompt
    assert "update-cdn-sync.net -> MALICIOUS" in prompt


def test_no_providers_skips_intel_nodes(make_analyzer, sample_alerts):
    result, trace = make_analyzer(llm_down(), providers=[]).analyze(
        credential_dumping(sample_alerts)
    )
    assert result.intel == []
    assert not any(t.startswith(("select_indicators", "enrich_indicators")) for t in trace)


def test_remote_provider_errors_do_not_break_analysis(make_analyzer, sample_alerts):
    class Down(IntelProvider):
        name = "down"
        supported_types = frozenset({IT.SHA256, IT.DOMAIN})

        def _lookup(self, indicator):
            raise ValueError("boom")

    result, _ = make_analyzer(
        llm_down(), providers=[LocalIntelProvider(INTEL_FILE), Down()]
    ).analyze(credential_dumping(sample_alerts))
    sha = result.intel[0]
    assert sha.verdict == Verdict.MALICIOUS  # local intel still answers
    assert [r.error is not None for r in sha.results] == [False, True]


def test_baseline_intel_bonus(sample_alerts):
    alert = credential_dumping(sample_alerts)

    def intel(verdict):
        ind = Indicator(type=IT.DOMAIN, value="x.example.com")
        return [IndicatorIntel(indicator=ind, verdict=verdict, score=90)]

    base = baseline_score(alert.model_copy(update={"severity": Severity.LOW}), [])
    low = alert.model_copy(update={"severity": Severity.LOW})
    assert baseline_score(low, [], intel(Verdict.MALICIOUS)) == base + 15
    assert baseline_score(low, [], intel(Verdict.SUSPICIOUS)) == base + 7
    assert baseline_score(low, [], intel(Verdict.HARMLESS)) == base
    recs = fallback_recommendations(low, Severity.HIGH, intel(Verdict.SUSPICIOUS))
    assert not recs[0].action.startswith("Block known-malicious")

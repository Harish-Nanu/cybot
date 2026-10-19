import pytest

from cybot.agent import ThreatAnalyzer
from cybot.agent.heuristics import baseline_score, level_from_score
from cybot.agent.prompts import RecommendationList, RelevanceGrades, SearchQueries
from cybot.config import Settings
from cybot.models import (
    Priority,
    Recommendation,
    ResponsePhase,
    RiskAssessment,
    Severity,
)
from tests.conftest import FakeLLM


def credential_dumping(alerts):
    return next(a for a in alerts if a.title == "Credential Dumping")


def assessment(score=88, level=Severity.LOW):
    return RiskAssessment(
        risk_score=score,
        risk_level=level,
        summary="Active intrusion on WS-FIN-07",
        rationale="Mimikatz plus C2 and exfiltration on the same host [1]",
        mitre_techniques=["T1071.001"],
        confidence=0.9,
    )


RECS = RecommendationList(
    recommendations=[
        Recommendation(
            action="Isolate WS-FIN-07",
            phase=ResponsePhase.CONTAINMENT,
            priority=Priority.IMMEDIATE,
        )
    ]
)


@pytest.fixture
def make_analyzer(repo, knowledge_base, sample_alerts):
    repo.add_alerts(sample_alerts)

    def _make(llm, **overrides):
        settings = Settings(**{"max_retrieval_attempts": 2, "retrieval_k": 4, **overrides})
        return ThreatAnalyzer(repo, knowledge_base, llm, settings)

    return _make


def test_full_workflow(make_analyzer, repo, sample_alerts):
    llm = FakeLLM(
        {
            "SearchQueries": SearchQueries(queries=["mimikatz lsass", "WS-FIN-07 asset"]),
            "RelevanceGrades": RelevanceGrades(relevant=[1, 2, 2, 99]),
            "RiskAssessment": assessment(),
            "RecommendationList": RECS,
        }
    )
    alert = credential_dumping(sample_alerts)
    result, trace = make_analyzer(llm).analyze(alert)

    assert result.assessment.risk_score == 88
    assert result.assessment.risk_level == Severity.CRITICAL  # derived from score bands
    assert result.assessment.mitre_techniques == ["T1003.001", "T1071.001"]
    assert result.recommendations == RECS.recommendations
    assert len(result.references) == 2  # duplicates / out-of-range indices ignored
    assert result.retrieval_attempts == 1
    assert len(result.related_alert_ids) >= 3
    assert result.model == "fake-llm"
    assert repo.latest_analysis(alert.id) == result

    assert [t.split(":")[0] for t in trace] == [
        "correlate",
        "plan_queries",
        "retrieve (attempt 1)",
        "grade_documents",
        "assess_risk",
        "recommend_actions",
    ]
    # The assessment prompt carries correlated alerts and retrieved context.
    (assess_prompt,) = llm.called("RiskAssessment")
    assert "Excessive Outbound Data Transfer" in assess_prompt
    assert "[1]" in assess_prompt


def test_rewrites_queries_when_context_insufficient(make_analyzer, sample_alerts):
    llm = FakeLLM(
        {
            "SearchQueries": [
                SearchQueries(queries=["unrelated"]),
                SearchQueries(queries=["credential dumping lsass playbook"]),
            ],
            "RelevanceGrades": [RelevanceGrades(relevant=[]), RelevanceGrades(relevant=[1, 2])],
            "RiskAssessment": assessment(),
            "RecommendationList": RECS,
        }
    )
    result, trace = make_analyzer(llm).analyze(credential_dumping(sample_alerts))
    assert result.retrieval_attempts == 2
    assert len(llm.called("SearchQueries")) == 2
    assert any(t.startswith("rewrite_queries") for t in trace)
    assert len(result.references) == 2


def test_retry_budget_is_bounded(make_analyzer, sample_alerts):
    llm = FakeLLM(
        {
            "SearchQueries": SearchQueries(queries=["x"]),
            "RelevanceGrades": RelevanceGrades(relevant=[]),
            "RiskAssessment": assessment(),
            "RecommendationList": RECS,
        }
    )
    result, _ = make_analyzer(llm, max_retrieval_attempts=3).analyze(
        credential_dumping(sample_alerts)
    )
    assert result.retrieval_attempts == 3
    assert result.references == []


def test_degrades_gracefully_without_llm(make_analyzer, repo, sample_alerts):
    llm = FakeLLM(default_error=ConnectionError("ollama down"))
    alert = credential_dumping(sample_alerts)
    result, trace = make_analyzer(llm).analyze(alert)

    related = repo.find_related(alert)
    assert result.assessment.risk_score == baseline_score(alert, related)
    assert result.assessment.risk_level == Severity.CRITICAL
    assert "Heuristic" in result.assessment.rationale
    assert any("Isolate" in r.action for r in result.recommendations)
    assert result.references  # similarity-based fallback still provides context
    assert all("LLM failed" in t for t in trace if t.startswith(("plan", "assess", "recommend")))


def test_heuristics():
    assert level_from_score(85) == Severity.CRITICAL
    assert level_from_score(60) == Severity.HIGH
    assert level_from_score(40) == Severity.MEDIUM
    assert level_from_score(5) == Severity.INFORMATIONAL


def test_baseline_increases_with_correlation(sample_alerts):
    alert = credential_dumping(sample_alerts)
    others = [a for a in sample_alerts if a is not alert]
    assert baseline_score(alert, others) > baseline_score(alert, [])
    assert baseline_score(alert, others) <= 100

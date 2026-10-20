import httpx
import pytest

from cybot.agent import Decision, DecisionError, ThreatAnalyzer
from cybot.agent.checkpoint import build_checkpointer
from cybot.config import Settings
from cybot.intel.providers import LocalIntelProvider
from cybot.intel.service import ThreatIntelService
from cybot.models import (
    ActionEvent,
    ActionStatus,
    ActionType,
    Indicator,
    IndicatorIntel,
    IntelResult,
    NormalizedAlert,
    Recommendation,
    ResponseAction,
    RiskAssessment,
    Severity,
)
from cybot.rag import RetrievedChunk
from cybot.response import ResponsePlanner, ResponsePolicy, WebhookConnector
from cybot.response.planner import ActionProposals, ProposedAction
from tests.conftest import INTEL_FILE, POLICY_FILE, FakeLLM


def dumping(alerts):
    return next(a for a in alerts if a.title == "Credential Dumping")


def scripted(*proposals, score=92):
    return FakeLLM(
        {
            "RiskAssessment": RiskAssessment(
                risk_score=score, risk_level=Severity.CRITICAL, summary="s", rationale="r"
            ),
            "ActionProposals": ActionProposals(actions=[ProposedAction(**p) for p in proposals]),
        },
        default_error=ConnectionError("unscripted"),
    )


@pytest.fixture
def make_analyzer(repo, knowledge_base, sample_alerts, tmp_path):
    repo.add_alerts(sample_alerts)

    def _make(llm, connector=None):
        return ThreatAnalyzer(
            repo,
            knowledge_base,
            llm,
            Settings(),
            ThreatIntelService([LocalIntelProvider(INTEL_FILE)], repo),
            planner=ResponsePlanner(llm, ResponsePolicy.load(POLICY_FILE)),
            connector=connector,
            checkpointer=build_checkpointer(tmp_path / "checkpoints.db"),
        )

    return _make


def statuses(repo, analysis_id):
    return {(a.type, a.target): a.status for a in repo.list_actions(analysis_id=analysis_id)}


ISOLATE = {"type": "isolate_host", "target": "WS-FIN-07"}
RESET = {"type": "reset_credentials", "target": "j.doe"}
DISABLE = {"type": "disable_account", "target": "j.doe"}


def test_auto_actions_run_then_pauses_for_approval(make_analyzer, repo, sample_alerts):
    analyzer = make_analyzer(scripted(ISOLATE, RESET))
    alert = dumping(sample_alerts)
    result, trace = analyzer.analyze(alert)

    assert analyzer.is_waiting(result.id)
    found = statuses(repo, result.id)
    assert found[(ActionType.ISOLATE_HOST, "WS-FIN-07")] == ActionStatus.SIMULATED
    assert found[(ActionType.BLOCK_HASH, alert.indicators[0].value)] == ActionStatus.SIMULATED
    assert found[(ActionType.RESET_CREDENTIALS, "j.doe")] == ActionStatus.PENDING_APPROVAL
    assert trace[-2].startswith("plan_response")
    assert trace[-1].startswith("execute_actions") and "1 awaiting approval" in trace[-1]
    # The analysis itself is stored even though the run is paused.
    assert repo.latest_analysis(alert.id).id == result.id


def test_decisions_resume_until_done(make_analyzer, repo, sample_alerts):
    analyzer = make_analyzer(scripted(RESET, DISABLE))
    result, _ = analyzer.analyze(dumping(sample_alerts))
    pending = repo.list_actions(analysis_id=result.id, status=ActionStatus.PENDING_APPROVAL)
    reset = next(a for a in pending if a.type == ActionType.RESET_CREDENTIALS)
    disable = next(a for a in pending if a.type == ActionType.DISABLE_ACCOUNT)

    trace = analyzer.decide(result.id, [Decision(reset.id, True, "confirmed")], "alice")
    assert trace[0] == "await_approval: alice approved 1, rejected 0"
    assert "1 simulated" in trace[1] and "1 awaiting approval" in trace[1]
    assert analyzer.is_waiting(result.id)

    analyzer.decide(result.id, [Decision(disable.id, False, "reset is enough")], "bob")
    assert not analyzer.is_waiting(result.id)

    done_reset, done_disable = repo.get_action(reset.id), repo.get_action(disable.id)
    assert done_reset.status == ActionStatus.SIMULATED
    assert [(e.status, e.actor) for e in done_reset.history] == [
        (ActionStatus.PENDING_APPROVAL, "policy"),
        (ActionStatus.APPROVED, "alice"),
        (ActionStatus.SIMULATED, "connector:simulated"),
    ]
    assert done_disable.status == ActionStatus.REJECTED
    assert done_disable.history[-1].note == "reset is enough"


def test_paused_run_survives_restart(make_analyzer, repo, sample_alerts):
    result, _ = make_analyzer(scripted(RESET)).analyze(dumping(sample_alerts))
    (reset,) = repo.list_actions(analysis_id=result.id, status=ActionStatus.PENDING_APPROVAL)

    restarted = make_analyzer(scripted())  # new workflow + checkpointer, same database file
    restarted.decide(result.id, [Decision(reset.id, True)], "alice")
    assert repo.get_action(reset.id).status == ActionStatus.SIMULATED


def test_checkpointed_state_keeps_its_types(make_analyzer, sample_alerts):
    # Types missing from the checkpoint allowlist are silently restored as plain dicts.
    result, _ = make_analyzer(scripted(RESET)).analyze(dumping(sample_alerts))
    workflow = make_analyzer(scripted()).workflow
    values = workflow.graph.get_state(workflow._config(result.id)).values

    expected = {
        "alert": NormalizedAlert,
        "related_alerts": NormalizedAlert,
        "intel_candidates": Indicator,
        "intel": IndicatorIntel,
        "retrieved": RetrievedChunk,
        "context": RetrievedChunk,
        "assessment": RiskAssessment,
        "recommendations": Recommendation,
        "actions": ResponseAction,
    }
    for key, cls in expected.items():
        items = values[key] if isinstance(values[key], list) else [values[key]]
        assert items, key
        assert all(isinstance(item, cls) for item in items), (key, type(items[0]))
    assert isinstance(values["intel"][0].results[0], IntelResult)
    assert isinstance(values["actions"][0].history[0], ActionEvent)
    assert isinstance(values["actions"][0].status, ActionStatus)
    assert isinstance(values["alert"].indicators[0], Indicator)


def test_completes_without_pause_when_everything_is_auto(make_analyzer, repo, sample_alerts):
    analyzer = make_analyzer(scripted(ISOLATE))
    result, trace = analyzer.analyze(dumping(sample_alerts))
    assert not analyzer.is_waiting(result.id)
    assert ActionStatus.PENDING_APPROVAL not in statuses(repo, result.id).values()
    assert "awaiting approval" not in trace[-1]


def test_invalid_decisions_are_rejected(make_analyzer, repo, sample_alerts):
    analyzer = make_analyzer(scripted(RESET))
    result, _ = analyzer.analyze(dumping(sample_alerts))
    executed = next(
        a for a in repo.list_actions(analysis_id=result.id) if a.status == ActionStatus.SIMULATED
    )
    with pytest.raises(DecisionError, match="no decisions"):
        analyzer.decide(result.id, [], "alice")
    with pytest.raises(DecisionError, match="not pending"):
        analyzer.decide(result.id, [Decision("nope", True)], "alice")
    with pytest.raises(DecisionError, match="not pending"):
        analyzer.decide(result.id, [Decision(executed.id, True)], "alice")
    with pytest.raises(DecisionError, match="not awaiting approval"):
        analyzer.decide("unknown-analysis", [Decision("x", True)], "alice")


def test_connector_failures_are_recorded(make_analyzer, repo, sample_alerts):
    failing = WebhookConnector(
        "https://soar.example/hook",
        client=httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(503))),
    )
    result, trace = make_analyzer(scripted(ISOLATE), connector=failing).analyze(
        dumping(sample_alerts)
    )
    found = statuses(repo, result.id)
    assert found[(ActionType.ISOLATE_HOST, "WS-FIN-07")] == ActionStatus.FAILED
    isolate = next(
        a for a in repo.list_actions(analysis_id=result.id) if a.type == ActionType.ISOLATE_HOST
    )
    assert isolate.result == "HTTP 503" and isolate.connector == "webhook"
    assert "failed" in trace[-1]

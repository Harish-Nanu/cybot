import pytest

from cybot.models import (
    ActionStatus,
    ActionType,
    ApprovalMode,
    Indicator,
    IndicatorIntel,
    IndicatorType,
    Priority,
    Recommendation,
    ResponsePhase,
    RiskAssessment,
    Verdict,
)
from cybot.response import ResponsePlanner, ResponsePolicy
from cybot.response.planner import ActionProposals, ProposedAction
from tests.conftest import POLICY_FILE, FakeLLM

IT = IndicatorType
C2_DOMAIN = Indicator(type=IT.DOMAIN, value="update-cdn-sync.net")


def assessment(score):
    from cybot.agent.heuristics import level_from_score

    return RiskAssessment(
        risk_score=score, risk_level=level_from_score(score), summary="s", rationale="r"
    )


RECS = [
    Recommendation(
        action="Isolate WS-FIN-07", phase=ResponsePhase.CONTAINMENT, priority=Priority.IMMEDIATE
    )
]
MALICIOUS_INTEL = [IndicatorIntel(indicator=C2_DOMAIN, verdict=Verdict.MALICIOUS, score=95)]


@pytest.fixture
def dumping(sample_alerts):
    alert = next(a for a in sample_alerts if a.title == "Credential Dumping")
    related = [a for a in sample_alerts if a.source in ("suricata", "splunk")]
    return alert, related


def plan(llm, alert, related, score=92, intel=MALICIOUS_INTEL):
    planner = ResponsePlanner(llm, ResponsePolicy.load(POLICY_FILE))
    return planner.plan(
        alert=alert,
        analysis_id="an-1",
        assessment=assessment(score),
        recommendations=RECS,
        related=related,
        intel=intel,
    )


def by_key(actions):
    return {(a.type, a.target): a for a in actions}


def proposals(*items):
    return FakeLLM(
        {"ActionProposals": ActionProposals(actions=[ProposedAction(**i) for i in items])}
    )


def test_llm_proposals_are_validated_and_policy_applied(dumping):
    alert, related = dumping
    llm = proposals(
        {
            "type": "isolate_host",
            "target": "ws-fin-07",
            "reason": "contain",
            "priority": "immediate",
        },
        {"type": "reset_credentials", "target": "J.DOE", "priority": "high"},
        {"type": "block_ip", "target": "10.0.2.57"},  # internal -> denied by policy
        {"type": "block_ip", "target": "6.6.6.6"},  # never seen in this incident -> dropped
        {"type": "launch_missiles", "target": "WS-FIN-07"},  # not in catalog -> dropped
        {"type": "isolate_host", "target": "WS-FIN-07"},  # duplicate
    )
    actions, note = plan(llm, alert, related)
    found = by_key(actions)

    isolate = found[(ActionType.ISOLATE_HOST, "WS-FIN-07")]  # canonical casing restored
    assert isolate.status == ActionStatus.APPROVED and isolate.approval == ApprovalMode.AUTO
    assert isolate.priority == Priority.IMMEDIATE
    assert isolate.history[0].actor == "policy"

    reset = found[(ActionType.RESET_CREDENTIALS, "j.doe")]
    assert reset.status == ActionStatus.PENDING_APPROVAL

    denied = found[(ActionType.BLOCK_IP, "10.0.2.57")]
    assert denied.status == ActionStatus.DENIED and "isolate_host" in denied.policy_reason

    assert (ActionType.BLOCK_IP, "6.6.6.6") not in found
    # Guardrails: intel-confirmed C2 domain is blocked, and a ticket is opened.
    assert found[(ActionType.BLOCK_DOMAIN, "update-cdn-sync.net")].status == ActionStatus.APPROVED
    assert found[(ActionType.OPEN_TICKET, alert.title)].status == ActionStatus.APPROVED
    assert "2 invalid dropped" in note and "+2 guardrail" in note
    assert "1 denied by policy" in note


def test_prompt_lists_only_known_targets(dumping):
    alert, related = dumping
    llm = proposals()
    plan(llm, alert, related)
    (prompt,) = llm.called("ActionProposals")
    assert "WS-FIN-07" in prompt and "10.0.2.57 (internal)" in prompt
    assert "update-cdn-sync.net" in prompt
    assert "6.6.6.6" not in prompt


def test_rule_based_plan_when_llm_down(dumping):
    alert, related = dumping
    actions, note = plan(FakeLLM(default_error=ConnectionError("down")), alert, related)
    keys = set(by_key(actions))
    assert {
        (ActionType.BLOCK_DOMAIN, "update-cdn-sync.net"),
        (ActionType.ISOLATE_HOST, "WS-FIN-07"),
        (ActionType.RESET_CREDENTIALS, "j.doe"),
        (ActionType.OPEN_TICKET, alert.title),
    } == keys
    assert "LLM failed, 4 rule-based" in note


def test_low_risk_needs_approval_and_no_ticket(dumping):
    alert, related = dumping
    llm = proposals({"type": "block_domain", "target": "update-cdn-sync.net"})
    actions, _ = plan(llm, alert, related, score=30)
    assert [(a.type, a.status) for a in actions] == [
        (ActionType.BLOCK_DOMAIN, ActionStatus.PENDING_APPROVAL)
    ]
    assert "below the auto-response threshold" in actions[0].policy_reason


def test_protected_host_requires_approval(sample_alerts):
    brute = next(a for a in sample_alerts if "brute force" in a.title)
    llm = proposals({"type": "isolate_host", "target": "web-srv-01"})
    actions, _ = plan(llm, brute, [], score=85, intel=[])
    isolate = by_key(actions)[(ActionType.ISOLATE_HOST, "web-srv-01")]
    assert isolate.status == ActionStatus.PENDING_APPROVAL
    assert "protected asset" in isolate.policy_reason

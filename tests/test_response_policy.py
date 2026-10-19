import pytest

from cybot.models import ActionStatus, ActionType, ApprovalMode, ResponseAction
from cybot.response import ResponsePolicy
from tests.conftest import POLICY_FILE

AUTO, APPROVAL, DENY = ApprovalMode.AUTO, ApprovalMode.REQUIRE_APPROVAL, ApprovalMode.DENY


@pytest.fixture(scope="module")
def policy():
    return ResponsePolicy.load(POLICY_FILE)


def action(atype, target):
    return ResponseAction(alert_id="a", analysis_id="x", type=atype, target=target)


@pytest.mark.parametrize(
    ("atype", "target", "risk", "expected"),
    [
        (ActionType.BLOCK_IP, "198.51.100.77", 90, AUTO),
        (ActionType.BLOCK_IP, "10.0.2.57", 90, DENY),  # internal range
        (ActionType.BLOCK_DOMAIN, "update-cdn-sync.net", 90, AUTO),
        (ActionType.BLOCK_DOMAIN, "mail.corp.example", 90, DENY),
        (ActionType.BLOCK_URL, "https://corp.example/login", 90, DENY),
        (ActionType.ISOLATE_HOST, "WS-FIN-07", 90, AUTO),
        (ActionType.ISOLATE_HOST, "web-srv-01", 99, APPROVAL),  # protected server
        (ActionType.DISABLE_ACCOUNT, "j.doe", 90, APPROVAL),  # policy default for accounts
        (ActionType.RESET_CREDENTIALS, "Deploy", 90, APPROVAL),
        (ActionType.BLOCK_HASH, "a" * 64, 40, APPROVAL),  # below auto threshold
        (ActionType.OPEN_TICKET, "alert", 10, AUTO),  # non-disruptive: no threshold
    ],
)
def test_policy_decisions(policy, atype, target, risk, expected):
    mode, reason = policy.evaluate(action(atype, target), risk)
    assert mode == expected, reason
    assert reason


def test_unlisted_action_uses_default(tmp_path):
    path = tmp_path / "p.toml"
    path.write_text('[global]\ndefault_mode = "deny"\n')
    mode, _ = ResponsePolicy.load(path).evaluate(action(ActionType.BLOCK_IP, "8.8.8.8"), 90)
    assert mode == DENY


def test_transition_records_audit_trail():
    a = action(ActionType.BLOCK_IP, "8.8.8.8")
    b = a.transition(ActionStatus.APPROVED, "alice", "confirmed C2").transition(
        ActionStatus.SIMULATED, "connector:simulated"
    )
    assert a.history == [] and a.status == ActionStatus.PENDING_APPROVAL  # copy, not mutated
    assert [e.status for e in b.history] == [ActionStatus.APPROVED, ActionStatus.SIMULATED]
    assert b.history[0].actor == "alice" and b.history[0].note == "confirmed C2"
    assert b.status.terminal and not ActionStatus.APPROVED.terminal


def test_target_types():
    assert ActionType.ISOLATE_HOST.target_types == {"host"}
    assert ActionType.OPEN_TICKET.target_types == frozenset()
    assert not ActionType.OPEN_TICKET.disruptive

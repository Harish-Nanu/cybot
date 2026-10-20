import json

import pytest

from cybot.response.planner import ActionProposals, ProposedAction
from tests.conftest import SAMPLES, FakeLLM


@pytest.fixture
def client(make_client):
    llm = FakeLLM(
        {
            "ActionProposals": ActionProposals(
                actions=[
                    ProposedAction(type="isolate_host", target="WS-FIN-07"),
                    ProposedAction(type="reset_credentials", target="j.doe"),
                ]
            )
        },
        default_error=ConnectionError("down"),
    )
    return make_client(llm)


def analyze_dumping(client):
    payload = json.loads((SAMPLES / "crowdstrike.json").read_text())[0]
    return client.post("/api/v1/analyze/crowdstrike", json=payload).json()


def test_analysis_returns_actions_and_pause_state(client):
    body = analyze_dumping(client)
    assert body["awaiting_approval"] is True
    by_type = {a["type"]: a for a in body["actions"]}
    assert by_type["isolate_host"]["status"] == "simulated"
    assert by_type["reset_credentials"]["status"] == "pending_approval"
    assert by_type["reset_credentials"]["history"][0]["actor"] == "policy"


def test_approval_queue_and_decision(client):
    body = analyze_dumping(client)
    analysis_id = body["analysis"]["id"]
    queue = client.get("/api/v1/actions", params={"status": "pending_approval"}).json()
    assert [a["type"] for a in queue] == ["reset_credentials"]

    resp = client.post(
        f"/api/v1/analyses/{analysis_id}/decisions",
        json={
            "analyst": "alice",
            "decisions": [{"action_id": queue[0]["id"], "approve": True, "note": "go"}],
        },
    )
    assert resp.status_code == 200
    out = resp.json()
    assert out["awaiting_approval"] is False
    assert out["trace"][0] == "await_approval: alice approved 1, rejected 0"
    action = client.get(f"/api/v1/actions/{queue[0]['id']}").json()
    assert action["status"] == "simulated"
    assert [e["actor"] for e in action["history"]] == ["policy", "alice", "connector:simulated"]
    assert client.get("/api/v1/actions", params={"status": "pending_approval"}).json() == []

    # Deciding again is a conflict: nothing is pending any more.
    again = client.post(
        f"/api/v1/analyses/{analysis_id}/decisions",
        json={"analyst": "alice", "decisions": [{"action_id": queue[0]["id"], "approve": True}]},
    )
    assert again.status_code == 409


def test_alert_audit_and_validation(client):
    body = analyze_dumping(client)
    alert_id = body["alert"]["id"]
    audit = client.get(f"/api/v1/alerts/{alert_id}/actions").json()
    assert {a["id"] for a in audit} == {a["id"] for a in body["actions"]}
    assert client.get("/api/v1/actions/missing").status_code == 404
    bad = client.post(
        f"/api/v1/analyses/{body['analysis']['id']}/decisions",
        json={"analyst": "", "decisions": []},
    )
    assert bad.status_code == 422


def test_response_disabled(make_client):
    client = make_client(response_enabled=False)
    body = analyze_dumping(client)
    assert body["actions"] == [] and body["awaiting_approval"] is False

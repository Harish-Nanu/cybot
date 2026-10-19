import json

from cybot.agent.prompts import RecommendationList, RelevanceGrades, SearchQueries
from cybot.models import Priority, Recommendation, ResponsePhase, RiskAssessment, Severity
from tests.conftest import SAMPLES, FakeLLM


def sample(source):
    return json.loads((SAMPLES / f"{source}.json").read_text())


def scripted_llm(score=72):
    return FakeLLM(
        {
            "SearchQueries": SearchQueries(queries=["ssh brute force"]),
            "RelevanceGrades": RelevanceGrades(relevant=[1, 2]),
            "RiskAssessment": RiskAssessment(
                risk_score=score, risk_level=Severity.HIGH, summary="s", rationale="r"
            ),
            "RecommendationList": RecommendationList(
                recommendations=[
                    Recommendation(
                        action="Block 203.0.113.45",
                        phase=ResponsePhase.CONTAINMENT,
                        priority=Priority.HIGH,
                    )
                ]
            ),
        }
    )


def test_analyze_stored_alert(make_client):
    client = make_client(scripted_llm())
    alert_id = client.post("/api/v1/ingest/wazuh", json=sample("wazuh")).json()["alerts"][0]["id"]

    resp = client.post(f"/api/v1/alerts/{alert_id}/analyze")
    assert resp.status_code == 200
    body = resp.json()
    assert body["alert"]["id"] == alert_id
    assert body["analysis"]["assessment"]["risk_score"] == 72
    assert body["analysis"]["recommendations"][0]["action"] == "Block 203.0.113.45"
    assert body["trace"][0].startswith("correlate")

    history = client.get(f"/api/v1/alerts/{alert_id}/analyses").json()
    assert [a["id"] for a in history] == [body["analysis"]["id"]]


def test_analyze_missing_alert(make_client):
    assert make_client().post("/api/v1/alerts/nope/analyze").status_code == 404


def test_ingest_and_analyze_one_shot(make_client):
    client = make_client(scripted_llm(score=91))
    payload = sample("crowdstrike")[0]
    resp = client.post("/api/v1/analyze/crowdstrike", json=payload)
    assert resp.status_code == 200
    assert resp.json()["analysis"]["assessment"]["risk_level"] == "critical"

    assert client.post("/api/v1/analyze/crowdstrike", json=payload).status_code == 409
    assert client.post("/api/v1/analyze/crowdstrike", json={"x": 1}).status_code == 422
    assert client.post("/api/v1/analyze/nope", json=payload).status_code == 404


def test_ingest_with_background_analysis_and_triage_queue(make_client):
    client = make_client(scripted_llm(score=65))
    body = client.post("/api/v1/ingest/suricata?analyze=true", json=sample("suricata")).json()
    # TestClient runs background tasks before returning.
    for alert in body["alerts"]:
        assert client.get(f"/api/v1/alerts/{alert['id']}/analyses").json()

    queue = client.get("/api/v1/analyses", params={"min_score": 60}).json()
    assert len(queue) == 2
    assert client.get("/api/v1/analyses", params={"min_score": 70}).json() == []


def test_analysis_falls_back_when_llm_down(make_client):
    client = make_client()  # default FakeLLM raises for every call
    body = client.post("/api/v1/analyze/crowdstrike", json=sample("crowdstrike")[0]).json()
    assert "Heuristic" in body["analysis"]["assessment"]["rationale"]
    assert body["analysis"]["recommendations"]


def test_knowledge_endpoints(make_client):
    client = make_client()
    stats = client.get("/api/v1/knowledge/stats").json()
    assert stats["documents"] == 19 and stats["embedder"] == "hashing"

    hits = client.post(
        "/api/v1/knowledge/search", json={"query": "mimikatz lsass credential dumping", "k": 2}
    ).json()
    assert len(hits) == 2
    assert "credential" in hits[0]["doc_id"].lower() or "T1003" in hits[0]["doc_id"]

    assert client.post("/api/v1/knowledge/reindex").json() == stats
    assert client.post("/api/v1/knowledge/search", json={"query": ""}).status_code == 422

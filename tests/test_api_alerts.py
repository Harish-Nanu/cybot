import json

import pytest

from tests.conftest import SAMPLES


@pytest.fixture
def client(make_client):
    return make_client()


def sample(source):
    return json.loads((SAMPLES / f"{source}.json").read_text())


def test_list_sources(client):
    sources = {s["source"] for s in client.get("/api/v1/sources").json()}
    assert sources == {"generic", "suricata", "wazuh", "crowdstrike", "splunk"}


def test_ingest_list_and_get(client):
    resp = client.post("/api/v1/ingest/wazuh", json=sample("wazuh"))
    assert resp.status_code == 201
    body = resp.json()
    assert (body["received"], body["ingested"], body["duplicates"]) == (2, 2, 0)

    page = client.get("/api/v1/alerts", params={"source": "wazuh"}).json()
    assert page["total"] == 2

    alert_id = body["alerts"][0]["id"]
    alert = client.get(f"/api/v1/alerts/{alert_id}").json()
    assert alert["source"] == "wazuh"
    assert alert["raw"]["rule"]["id"]


def test_ingest_single_object_and_duplicates(client):
    payload = sample("crowdstrike")[0]
    first = client.post("/api/v1/ingest/crowdstrike", json=payload).json()
    again = client.post("/api/v1/ingest/crowdstrike", json=payload).json()
    assert first["ingested"] == 1
    assert (again["ingested"], again["duplicates"]) == (0, 1)


def test_ingest_partial_errors(client):
    payloads = [*sample("suricata"), {"not": "suricata"}]
    body = client.post("/api/v1/ingest/suricata", json=payloads).json()
    assert body["ingested"] == 2
    assert body["errors"][0]["index"] == 2


def test_ingest_all_invalid_returns_422(client):
    resp = client.post("/api/v1/ingest/splunk", json=[{"bad": 1}])
    assert resp.status_code == 422


def test_unknown_source_404(client):
    assert client.post("/api/v1/ingest/unknown", json={}).status_code == 404


def test_filters_and_related(client):
    for source in ("suricata", "wazuh", "crowdstrike", "splunk", "generic"):
        client.post(f"/api/v1/ingest/{source}", json=sample(source))
    high = client.get("/api/v1/alerts", params={"min_severity": "high"}).json()
    assert high["total"] >= 4
    assert all(a["severity"] in ("high", "critical") for a in high["items"])

    edr = client.get("/api/v1/alerts", params={"source": "crowdstrike"}).json()["items"][0]
    related = client.get(f"/api/v1/alerts/{edr['id']}/related").json()
    assert {"splunk", "suricata", "generic"} <= {a["source"] for a in related}


def test_missing_alert_404(client):
    assert client.get("/api/v1/alerts/nope").status_code == 404


def test_api_key_enforced(make_client):
    client = make_client(api_key="s3cret")
    assert client.get("/api/v1/sources").status_code == 401
    assert client.get("/api/v1/sources", headers={"X-API-Key": "wrong"}).status_code == 401
    assert client.get("/api/v1/sources", headers={"X-API-Key": "s3cret"}).status_code == 200
    assert client.get("/health").status_code == 200  # health stays open

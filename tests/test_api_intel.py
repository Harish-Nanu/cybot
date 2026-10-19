import json

from tests.conftest import SAMPLES


def test_providers_and_lookup(make_client):
    client = make_client()
    assert client.get("/api/v1/intel/providers").json() == {
        "enabled": True,
        "providers": ["local"],
    }
    body = client.post("/api/v1/intel/lookup", json={"value": "update-cdn-sync.net"}).json()
    assert body["indicator"] == {"type": "domain", "value": "update-cdn-sync.net"}
    assert body["verdict"] == "malicious"
    assert body["results"][0]["provider"] == "local"


def test_lookup_explicit_type_and_undetectable(make_client):
    client = make_client()
    body = client.post("/api/v1/intel/lookup", json={"value": "8.8.8.8", "type": "ip"}).json()
    assert body["verdict"] == "unknown"
    resp = client.post("/api/v1/intel/lookup", json={"value": "not an indicator"})
    assert resp.status_code == 422


def test_enrich_alert(make_client):
    client = make_client()
    payload = json.loads((SAMPLES / "crowdstrike.json").read_text())
    alert_id = client.post("/api/v1/ingest/crowdstrike", json=payload).json()["alerts"][0]["id"]

    intel = client.post(f"/api/v1/alerts/{alert_id}/enrich").json()
    assert intel[0]["indicator"]["type"] == "sha256"
    assert intel[0]["verdict"] == "malicious"
    assert len(client.post(f"/api/v1/alerts/{alert_id}/enrich?limit=1").json()) == 1
    assert client.post("/api/v1/alerts/missing/enrich").status_code == 404


def test_analysis_includes_intel(make_client):
    client = make_client()
    payload = json.loads((SAMPLES / "splunk.json").read_text())[0]
    body = client.post("/api/v1/analyze/splunk", json=payload).json()
    flagged = {
        i["indicator"]["value"] for i in body["analysis"]["intel"] if i["verdict"] == "malicious"
    }
    assert "198.51.100.77" in flagged


def test_intel_disabled_returns_503(make_client):
    client = make_client(intel_enabled=False)
    assert client.get("/api/v1/intel/providers").json() == {"enabled": False, "providers": []}
    assert client.post("/api/v1/intel/lookup", json={"value": "8.8.8.8"}).status_code == 503

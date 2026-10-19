from fastapi.testclient import TestClient

from cybot.config import Settings
from cybot.main import create_app


def test_health(tmp_path):
    client = TestClient(create_app(Settings(database_url=f"sqlite:///{tmp_path / 'h.db'}")))
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"

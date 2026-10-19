import json
from pathlib import Path

import pytest

from cybot.ingestion.normalizers import get_normalizer
from cybot.models import NormalizedAlert
from cybot.storage import AlertRepository, Database

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


@pytest.fixture
def db(tmp_path) -> Database:
    database = Database(f"sqlite:///{tmp_path / 'test.db'}")
    database.create_all()
    return database


@pytest.fixture
def repo(db) -> AlertRepository:
    return AlertRepository(db)


@pytest.fixture
def sample_alerts() -> list[NormalizedAlert]:
    """All sample payloads normalized, in a stable order."""
    alerts = []
    for source in ("suricata", "wazuh", "crowdstrike", "splunk", "generic"):
        for payload in json.loads((SAMPLES / f"{source}.json").read_text()):
            alerts.append(get_normalizer(source).normalize(payload))
    return alerts


KNOWLEDGE_DIR = Path(__file__).resolve().parents[1] / "knowledge"


@pytest.fixture
def knowledge_base(tmp_path):
    from cybot.rag import HashingEmbedder, KnowledgeBase

    kb = KnowledgeBase(HashingEmbedder(), collection="test_kb", persist_path=tmp_path / "chroma")
    kb.index_directory(KNOWLEDGE_DIR)
    return kb

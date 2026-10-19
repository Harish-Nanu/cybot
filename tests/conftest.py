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


class FakeLLM:
    """Scripted StructuredLLM: responses keyed by schema name.

    A value may be a model instance, a list (consumed one per call; last one repeats),
    an exception instance (raised), or a callable taking the prompt.
    """

    model_name = "fake-llm"

    def __init__(self, responses=None, default_error=None):
        self.responses = dict(responses or {})
        self.default_error = default_error
        self.calls: list[tuple[str, str]] = []

    def generate(self, schema, system, prompt):
        name = schema.__name__
        self.calls.append((name, prompt))
        if name not in self.responses:
            raise self.default_error or KeyError(f"no scripted response for {name}")
        value = self.responses[name]
        if isinstance(value, list):
            value = value.pop(0) if len(value) > 1 else value[0]
        if isinstance(value, Exception):
            raise value
        return value(prompt) if callable(value) else value

    def called(self, name):
        return [p for n, p in self.calls if n == name]

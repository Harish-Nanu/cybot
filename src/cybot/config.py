"""Application settings, loaded from environment variables / .env."""

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="CYBOT_", env_file=".env", extra="ignore")

    # API
    app_name: str = "Cybot Threat Analysis API"
    api_key: str | None = None  # when set, requests must send X-API-Key

    # Storage
    database_url: str = f"sqlite:///{PROJECT_ROOT / 'data' / 'cybot.db'}"

    # LLM (Ollama)
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.1:8b"
    llm_temperature: float = 0.0
    llm_timeout_seconds: float = 120.0
    # Ollama defaults to a 2048-token context, which truncates RAG prompts.
    ollama_num_ctx: int = 8192

    # RAG
    chroma_path: Path = PROJECT_ROOT / "data" / "chroma"
    chroma_collection: str = "security_knowledge"
    knowledge_dir: Path = PROJECT_ROOT / "knowledge"
    embedding_backend: str = "default"  # "default" (ONNX MiniLM) | "sentence-transformers"
    embedding_model: str = "all-MiniLM-L6-v2"
    retrieval_k: int = 4
    max_retrieval_attempts: int = 2
    auto_index_knowledge: bool = True  # build the index on startup if it is empty

    # Correlation
    correlation_window_hours: int = 24

    # Threat intelligence enrichment
    intel_enabled: bool = True
    intel_local_path: Path | None = PROJECT_ROOT / "intel" / "local_iocs.csv"
    abuseipdb_api_key: SecretStr | None = None
    virustotal_api_key: SecretStr | None = None
    greynoise_api_key: SecretStr | None = None
    urlhaus_api_key: SecretStr | None = None
    intel_timeout_seconds: float = 10.0
    intel_cache_ttl_hours: int = 24
    intel_max_lookups: int = 8  # indicators enriched per analysis

    # Automated response
    response_enabled: bool = True
    # dry_run: actions are only simulated; live: approved actions are sent to the webhook
    response_mode: Literal["dry_run", "live"] = "dry_run"
    response_policy_path: Path = PROJECT_ROOT / "policy" / "response_policy.toml"
    response_webhook_url: str | None = None
    response_webhook_secret: SecretStr | None = None
    response_timeout_seconds: float = 10.0
    # LangGraph checkpoints, so runs paused for approval survive restarts
    checkpoint_path: Path = PROJECT_ROOT / "data" / "checkpoints.db"


@lru_cache
def get_settings() -> Settings:
    return Settings()

"""Application settings, loaded from environment variables / .env."""

from functools import lru_cache
from pathlib import Path

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

    # Correlation
    correlation_window_hours: int = 24


@lru_cache
def get_settings() -> Settings:
    return Settings()

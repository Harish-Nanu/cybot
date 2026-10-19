"""Pluggable local embedding backends."""

from __future__ import annotations

import hashlib
import math
import re
from typing import Protocol

from cybot.config import Settings


class Embedder(Protocol):
    name: str

    def embed_documents(self, texts: list[str]) -> list[list[float]]: ...

    def embed_query(self, text: str) -> list[float]: ...


class OnnxMiniLMEmbedder:
    """all-MiniLM-L6-v2 via ONNX Runtime (bundled with chromadb; no torch required)."""

    name = "onnx-all-MiniLM-L6-v2"

    def __init__(self) -> None:
        from chromadb.utils.embedding_functions import ONNXMiniLM_L6_V2

        self._fn = ONNXMiniLM_L6_V2()

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return [list(map(float, v)) for v in self._fn(texts)]

    def embed_query(self, text: str) -> list[float]:
        return self.embed_documents([text])[0]


class SentenceTransformerEmbedder:
    """Any sentence-transformers model (install the `sentence-transformers` extra)."""

    def __init__(self, model_name: str) -> None:
        from sentence_transformers import SentenceTransformer

        self.name = f"st-{model_name}"
        self._model = SentenceTransformer(model_name)

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return self._model.encode(texts, normalize_embeddings=True).tolist()

    def embed_query(self, text: str) -> list[float]:
        return self.embed_documents([text])[0]


class OllamaEmbedder:
    """Embeddings served by Ollama, e.g. `nomic-embed-text`."""

    def __init__(self, model_name: str, base_url: str) -> None:
        from langchain_ollama import OllamaEmbeddings

        self.name = f"ollama-{model_name}"
        self._emb = OllamaEmbeddings(model=model_name, base_url=base_url)

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return self._emb.embed_documents(texts)

    def embed_query(self, text: str) -> list[float]:
        return self._emb.embed_query(text)


class HashingEmbedder:
    """Dependency-free bag-of-words hashing embedder; deterministic, for tests and offline demos."""

    name = "hashing"

    def __init__(self, dim: int = 512) -> None:
        self.dim = dim

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return [self.embed_query(t) for t in texts]

    def embed_query(self, text: str) -> list[float]:
        vec = [0.0] * self.dim
        for token in re.findall(r"[a-z0-9]+", text.lower()):
            digest = int(hashlib.md5(token.encode()).hexdigest(), 16)
            vec[digest % self.dim] += 1.0
        norm = math.sqrt(sum(v * v for v in vec)) or 1.0
        return [v / norm for v in vec]


def build_embedder(settings: Settings) -> Embedder:
    backend = settings.embedding_backend.lower()
    if backend == "default":
        return OnnxMiniLMEmbedder()
    if backend == "sentence-transformers":
        return SentenceTransformerEmbedder(settings.embedding_model)
    if backend == "ollama":
        return OllamaEmbedder(settings.embedding_model, settings.ollama_base_url)
    if backend == "hashing":
        return HashingEmbedder()
    raise ValueError(f"Unknown embedding backend: {settings.embedding_backend}")

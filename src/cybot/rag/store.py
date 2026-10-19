"""Chroma-backed vector store for the security knowledge base."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import chromadb

from cybot.rag.documents import KnowledgeChunk, load_directory
from cybot.rag.embeddings import Embedder

_BATCH = 64


@dataclass
class RetrievedChunk:
    id: str
    doc_id: str
    title: str
    section: str
    text: str
    score: float  # cosine similarity, higher is better
    doc_type: str = ""
    mitre: str = ""


class KnowledgeBase:
    def __init__(
        self,
        embedder: Embedder,
        *,
        collection: str = "security_knowledge",
        persist_path: Path | None = None,
    ) -> None:
        self.embedder = embedder
        self.collection_name = collection
        if persist_path is None:
            self._client = chromadb.EphemeralClient()
        else:
            persist_path.mkdir(parents=True, exist_ok=True)
            self._client = chromadb.PersistentClient(path=str(persist_path))
        self._collection = self._get_collection()

    def _get_collection(self):
        return self._client.get_or_create_collection(
            self.collection_name,
            embedding_function=None,
            configuration={"hnsw": {"space": "cosine"}},
            metadata={"embedder": self.embedder.name},
        )

    def count(self) -> int:
        return self._collection.count()

    def reset(self) -> None:
        self._client.delete_collection(self.collection_name)
        self._collection = self._get_collection()

    def add_chunks(self, chunks: list[KnowledgeChunk]) -> int:
        for start in range(0, len(chunks), _BATCH):
            batch = chunks[start : start + _BATCH]
            self._collection.upsert(
                ids=[c.id for c in batch],
                documents=[c.text for c in batch],
                metadatas=[c.metadata() for c in batch],
                embeddings=self.embedder.embed_documents([c.text for c in batch]),
            )
        return len(chunks)

    def index_directory(self, directory: Path, *, reset: bool = True) -> int:
        """(Re)build the index from all markdown documents in a directory."""
        chunks = load_directory(directory)
        if reset:
            self.reset()
        return self.add_chunks(chunks)

    def search(self, query: str, k: int = 4, *, min_score: float = 0.0) -> list[RetrievedChunk]:
        if not query.strip() or self.count() == 0:
            return []
        result = self._collection.query(
            query_embeddings=[self.embedder.embed_query(query)],
            n_results=min(k, self.count()),
            include=["documents", "metadatas", "distances"],
        )
        hits = []
        for chunk_id, doc, meta, dist in zip(
            result["ids"][0],
            result["documents"][0],
            result["metadatas"][0],
            result["distances"][0],
            strict=True,
        ):
            score = 1.0 - float(dist)
            if score < min_score:
                continue
            hits.append(
                RetrievedChunk(
                    id=chunk_id,
                    doc_id=str(meta.get("doc_id", "")),
                    title=str(meta.get("title", "")),
                    section=str(meta.get("section", "")),
                    text=doc or "",
                    score=round(score, 4),
                    doc_type=str(meta.get("doc_type", "")),
                    mitre=str(meta.get("mitre", "")),
                )
            )
        return hits

    def stats(self) -> dict[str, object]:
        metas = self._collection.get(include=["metadatas"])["metadatas"] or []
        return {
            "collection": self.collection_name,
            "embedder": self.embedder.name,
            "chunks": len(metas),
            "documents": len({m.get("doc_id") for m in metas}),
        }

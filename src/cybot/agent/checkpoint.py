"""LangGraph checkpointing, so workflows paused for human approval survive restarts."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
from langgraph.checkpoint.sqlite import SqliteSaver

from cybot import models
from cybot.rag import RetrievedChunk

# Types stored in the graph state. They are allow-listed explicitly because LangGraph
# is moving to refuse deserializing unregistered classes from checkpoints.
STATE_TYPES: tuple[type, ...] = (
    models.NormalizedAlert,
    models.Indicator,
    models.IndicatorType,
    models.Severity,
    models.AlertCategory,
    models.RiskAssessment,
    models.Recommendation,
    models.ResponsePhase,
    models.Priority,
    models.Likelihood,
    models.IndicatorIntel,
    models.IntelResult,
    models.Verdict,
    models.ResponseAction,
    models.ActionEvent,
    models.ActionType,
    models.ApprovalMode,
    models.ActionStatus,
    RetrievedChunk,
)


def serializer() -> JsonPlusSerializer:
    return JsonPlusSerializer(
        allowed_msgpack_modules=[(cls.__module__, cls.__qualname__) for cls in STATE_TYPES]
    )


def build_checkpointer(path: Path | None) -> BaseCheckpointSaver:
    """SQLite-backed checkpointer at ``path``, or in-memory when ``path`` is None."""
    if path is None:
        return InMemorySaver(serde=serializer())
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False)
    return SqliteSaver(conn, serde=serializer())

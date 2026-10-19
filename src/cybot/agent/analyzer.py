"""High-level entry point: run the workflow for an alert and persist the result."""

from __future__ import annotations

import time

from cybot.agent.graph import AnalysisWorkflow
from cybot.agent.llm import StructuredLLM
from cybot.config import Settings
from cybot.models import AnalysisResult, KnowledgeReference, NormalizedAlert
from cybot.rag import KnowledgeBase
from cybot.storage import AlertRepository


class ThreatAnalyzer:
    def __init__(
        self,
        repo: AlertRepository,
        knowledge: KnowledgeBase,
        llm: StructuredLLM,
        settings: Settings,
    ) -> None:
        self.repo = repo
        self.llm = llm
        self.workflow = AnalysisWorkflow(
            repo,
            knowledge,
            llm,
            retrieval_k=settings.retrieval_k,
            max_retrieval_attempts=settings.max_retrieval_attempts,
            correlation_window_hours=settings.correlation_window_hours,
        )

    def analyze(self, alert: NormalizedAlert) -> tuple[AnalysisResult, list[str]]:
        """Analyze a stored alert; returns the persisted result and the workflow trace."""
        started = time.perf_counter()
        state = self.workflow.run(alert)
        result = AnalysisResult(
            alert_id=alert.id,
            assessment=state["assessment"],
            recommendations=state.get("recommendations", []),
            related_alert_ids=[a.id for a in state.get("related_alerts", [])],
            references=[
                KnowledgeReference(
                    doc_id=c.doc_id, title=f"{c.title} / {c.section}", source=c.id, score=c.score
                )
                for c in state.get("context", [])
            ],
            model=self.llm.model_name,
            retrieval_attempts=state.get("retrieval_attempts", 0),
            duration_ms=int((time.perf_counter() - started) * 1000),
        )
        self.repo.save_analysis(result)
        return result, state.get("trace", [])

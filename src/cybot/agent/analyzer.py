"""High-level entry point: run the workflow for an alert and persist the result."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass

from langgraph.checkpoint.base import BaseCheckpointSaver

from cybot.agent.graph import AnalysisWorkflow
from cybot.agent.llm import StructuredLLM
from cybot.config import Settings
from cybot.intel.service import ThreatIntelService
from cybot.models import AnalysisResult, KnowledgeReference, NormalizedAlert
from cybot.models.response import ActionStatus
from cybot.rag import KnowledgeBase
from cybot.response import ActionConnector, ResponsePlanner
from cybot.storage import AlertRepository


@dataclass
class Decision:
    action_id: str
    approve: bool
    note: str = ""


class DecisionError(ValueError):
    """Decisions that cannot be applied (unknown action, not pending, run not waiting)."""


class ThreatAnalyzer:
    def __init__(
        self,
        repo: AlertRepository,
        knowledge: KnowledgeBase,
        llm: StructuredLLM,
        settings: Settings,
        intel: ThreatIntelService | None = None,
        *,
        planner: ResponsePlanner | None = None,
        connector: ActionConnector | None = None,
        checkpointer: BaseCheckpointSaver | None = None,
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
            intel=intel,
            max_intel_lookups=settings.intel_max_lookups,
            planner=planner,
            connector=connector,
            checkpointer=checkpointer,
        )

    def analyze(self, alert: NormalizedAlert) -> tuple[AnalysisResult, list[str]]:
        """Analyze a stored alert; returns the persisted result and the workflow trace.

        When response actions need approval the run is paused (checkpointed under the
        analysis id) and auto-approved actions have already been carried out.
        """
        started = time.perf_counter()
        analysis_id = str(uuid.uuid4())
        state = self.workflow.run(alert, analysis_id)
        result = AnalysisResult(
            id=analysis_id,
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
            intel=state.get("intel", []),
            model=self.llm.model_name,
            retrieval_attempts=state.get("retrieval_attempts", 0),
            duration_ms=int((time.perf_counter() - started) * 1000),
        )
        self.repo.save_analysis(result)
        return result, state.get("trace", [])

    def decide(self, analysis_id: str, decisions: list[Decision], analyst: str) -> list[str]:
        """Apply approve/reject decisions to a paused run and continue it.

        Returns the workflow trace entries produced by the resumed run.
        """
        if not decisions:
            raise DecisionError("no decisions given")
        if not self.workflow.is_waiting(analysis_id):
            raise DecisionError(f"analysis {analysis_id} is not awaiting approval")
        pending = {
            a.id
            for a in self.repo.list_actions(analysis_id=analysis_id)
            if a.status == ActionStatus.PENDING_APPROVAL
        }
        unknown = [d.action_id for d in decisions if d.action_id not in pending]
        if unknown:
            raise DecisionError(f"actions not pending approval in this analysis: {unknown}")

        before = len(self.workflow.trace(analysis_id))
        state = self.workflow.resume(
            analysis_id,
            {
                "analyst": analyst,
                "decisions": [
                    {"action_id": d.action_id, "approve": d.approve, "note": d.note}
                    for d in decisions
                ],
            },
        )
        return state.get("trace", [])[before:]

    def is_waiting(self, analysis_id: str) -> bool:
        return self.workflow.is_waiting(analysis_id)

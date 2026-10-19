"""LangGraph agentic-RAG workflow for alert risk assessment.

correlate -> [select_indicators -> enrich_indicators] -> plan_queries -> retrieve
    -> grade_documents --(enough context)--> assess_risk -> recommend_actions
            |                    ^
            +--> rewrite_queries-+ (too little context, retry budget left)

The threat-intel steps run only when intel providers are configured.
"""

from __future__ import annotations

import logging
import operator
from typing import Annotated, Literal, TypedDict

from langgraph.graph import END, START, StateGraph

from cybot.agent import heuristics, prompts
from cybot.agent.llm import StructuredLLM
from cybot.intel import IndicatorIntel
from cybot.intel.service import ThreatIntelService
from cybot.models import (
    Indicator,
    IndicatorType,
    NormalizedAlert,
    Recommendation,
    ResponsePhase,
    RiskAssessment,
    Severity,
)
from cybot.rag import KnowledgeBase, RetrievedChunk
from cybot.storage import AlertRepository

logger = logging.getLogger(__name__)

MIN_RELEVANT_CHUNKS = 2
MAX_CONTEXT_CHUNKS = 8
MAX_CHUNKS_PER_DOC = 3
FALLBACK_MIN_SCORE = 0.25
RRF_K = 60
MAX_INTEL_CANDIDATES = 25
_HASH_TYPES = {IndicatorType.MD5, IndicatorType.SHA1, IndicatorType.SHA256}


class AgentState(TypedDict, total=False):
    alert: NormalizedAlert
    related_alerts: list[NormalizedAlert]
    intel_candidates: list[Indicator]
    intel: list[IndicatorIntel]
    queries: list[str]
    retrieved: list[RetrievedChunk]
    context: list[RetrievedChunk]
    retrieval_attempts: int
    assessment: RiskAssessment
    recommendations: list[Recommendation]
    trace: Annotated[list[str], operator.add]


class AnalysisWorkflow:
    def __init__(
        self,
        repo: AlertRepository,
        knowledge: KnowledgeBase,
        llm: StructuredLLM,
        *,
        retrieval_k: int = 4,
        max_retrieval_attempts: int = 2,
        correlation_window_hours: int = 24,
        intel: ThreatIntelService | None = None,
        max_intel_lookups: int = 8,
    ) -> None:
        self.repo = repo
        self.intel = intel if intel is not None and intel.providers else None
        self.max_intel_lookups = max_intel_lookups
        self.knowledge = knowledge
        self.llm = llm
        self.retrieval_k = retrieval_k
        self.max_retrieval_attempts = max_retrieval_attempts
        self.correlation_window_hours = correlation_window_hours
        self.graph = self._build()

    def _build(self):
        g = StateGraph(AgentState)
        g.add_node("correlate", self.correlate)
        g.add_node("select_indicators", self.select_indicators)
        g.add_node("enrich_indicators", self.enrich_indicators)
        g.add_node("plan_queries", self.plan_queries)
        g.add_node("retrieve", self.retrieve)
        g.add_node("grade_documents", self.grade_documents)
        g.add_node("rewrite_queries", self.rewrite_queries)
        g.add_node("assess_risk", self.assess_risk)
        g.add_node("recommend_actions", self.recommend_actions)

        g.add_edge(START, "correlate")
        if self.intel is not None:
            g.add_edge("correlate", "select_indicators")
            g.add_edge("select_indicators", "enrich_indicators")
            g.add_edge("enrich_indicators", "plan_queries")
        else:
            g.add_edge("correlate", "plan_queries")
        g.add_edge("plan_queries", "retrieve")
        g.add_edge("retrieve", "grade_documents")
        g.add_conditional_edges(
            "grade_documents",
            self.route_after_grading,
            {"rewrite": "rewrite_queries", "assess": "assess_risk"},
        )
        g.add_edge("rewrite_queries", "retrieve")
        g.add_edge("assess_risk", "recommend_actions")
        g.add_edge("recommend_actions", END)
        return g.compile()

    def run(self, alert: NormalizedAlert) -> AgentState:
        return self.graph.invoke({"alert": alert, "retrieval_attempts": 0, "trace": []})

    # -- nodes ----------------------------------------------------------------
    def correlate(self, state: AgentState) -> AgentState:
        related = self.repo.find_related(state["alert"], window_hours=self.correlation_window_hours)
        return {"related_alerts": related, "trace": [f"correlate: {len(related)} related alert(s)"]}

    def select_indicators(self, state: AgentState) -> AgentState:
        """Choose which indicators to spend the threat-intel lookup budget on."""
        assert self.intel is not None
        alert, related = state["alert"], state.get("related_alerts", [])
        own = self.intel.candidates(alert.indicators)
        own_keys = {(i.type, i.value.lower()) for i in own}
        from_related = [
            i
            for i in self.intel.candidates(ind for a in related for ind in a.indicators)
            if (i.type, i.value.lower()) not in own_keys
        ]
        # The alert's own indicators come first, each group ordered by specificity.
        candidates = [*own, *from_related][:MAX_INTEL_CANDIDATES]
        budget = self.max_intel_lookups

        if len(candidates) <= budget:
            note = f"select_indicators: all {len(candidates)} candidate(s) within budget"
            return {"intel_candidates": candidates, "trace": [note]}

        # The alert's own file hashes are the most specific evidence: always look them up
        # (using at most half the budget) and let the model choose the remaining slots.
        pinned = [i for i in own if i.type in _HASH_TYPES][: max(1, budget // 2)]
        rest = [c for c in candidates if c not in pinned]
        slots = budget - len(pinned)
        prefix = "select_indicators: " + (f"pinned {len(pinned)} hash(es), " if pinned else "")
        if slots <= 0:
            return {"intel_candidates": pinned, "trace": [prefix + "budget used"]}
        try:
            picked = self.llm.generate(
                prompts.IndicatorSelection,
                prompts.SYSTEM_ANALYST,
                prompts.select_indicators_prompt(alert, rest, slots),
            ).selected
            chosen = [rest[i - 1] for i in _dedupe(picked) if 1 <= i <= len(rest)][:slots]
            if not chosen:
                raise ValueError("model selected no valid indicators")
            note = f"LLM chose {len(chosen)}/{len(rest)}"
        except Exception as exc:
            logger.warning("Indicator selection failed: %s", exc)
            chosen = rest[:slots]
            note = f"LLM failed, top {slots}/{len(rest)} by priority"
        return {"intel_candidates": [*pinned, *chosen], "trace": [prefix + note]}

    def enrich_indicators(self, state: AgentState) -> AgentState:
        assert self.intel is not None
        intel = self.intel.enrich(state.get("intel_candidates", []))
        flagged = [i for i in intel if i.verdict in ("malicious", "suspicious")]
        cached = sum(r.cached for i in intel for r in i.results)
        note = f"enrich_indicators: {len(intel)} looked up, {len(flagged)} flagged"
        if cached:
            note += f", {cached} cached result(s)"
        return {"intel": intel, "trace": [note]}

    def plan_queries(self, state: AgentState) -> AgentState:
        alert = state["alert"]
        try:
            planned = self.llm.generate(
                prompts.SearchQueries,
                prompts.SYSTEM_ANALYST,
                prompts.plan_queries_prompt(
                    alert, state.get("related_alerts", []), state.get("intel", [])
                ),
            ).queries
            note = f"plan_queries: {len(planned)} LLM queries"
        except Exception as exc:  # any model failure falls back to defaults
            logger.warning("Query planning failed: %s", exc)
            planned, note = [], f"plan_queries: LLM failed ({type(exc).__name__}), using defaults"
        queries = _dedupe([*planned, *_default_queries(alert)])
        return {"queries": queries, "trace": [note]}

    def retrieve(self, state: AgentState) -> AgentState:
        # Reciprocal rank fusion: a broad query with uniformly high similarity scores
        # shouldn't crowd out the top hits of more specific queries.
        best: dict[str, RetrievedChunk] = {}
        fused: dict[str, float] = {}
        for query in state.get("queries", []):
            for rank, hit in enumerate(self.knowledge.search(query, k=self.retrieval_k)):
                fused[hit.id] = fused.get(hit.id, 0.0) + 1.0 / (RRF_K + rank)
                if hit.id not in best or hit.score > best[hit.id].score:
                    best[hit.id] = hit
        retrieved = sorted(best.values(), key=lambda c: fused[c.id], reverse=True)
        attempts = state.get("retrieval_attempts", 0) + 1
        return {
            "retrieved": retrieved,
            "retrieval_attempts": attempts,
            "trace": [f"retrieve (attempt {attempts}): {len(retrieved)} chunk(s)"],
        }

    def grade_documents(self, state: AgentState) -> AgentState:
        retrieved = state.get("retrieved", [])
        candidates = retrieved[: MAX_CONTEXT_CHUNKS * 2]
        previous = state.get("context", [])
        if not candidates:
            return {"context": previous, "trace": ["grade_documents: nothing to grade"]}
        try:
            grades = self.llm.generate(
                prompts.RelevanceGrades,
                prompts.SYSTEM_ANALYST,
                prompts.grade_prompt(state["alert"], candidates),
            )
            relevant = [
                candidates[i - 1] for i in _dedupe(grades.relevant) if 1 <= i <= len(candidates)
            ]
            note = f"grade_documents: {len(relevant)}/{len(candidates)} relevant"
        except Exception as exc:
            logger.warning("Relevance grading failed: %s", exc)
            relevant = [c for c in candidates if c.score >= FALLBACK_MIN_SCORE]
            note = f"grade_documents: LLM failed, kept {len(relevant)} by similarity"
        # Keep relevant material from earlier attempts when retrying with new queries.
        merged = {c.id: c for c in [*previous, *relevant]}
        context = _diversify(list(merged.values()))
        return {"context": context, "trace": [note]}

    def route_after_grading(self, state: AgentState) -> Literal["rewrite", "assess"]:
        enough = len(state.get("context", [])) >= MIN_RELEVANT_CHUNKS
        budget_left = state.get("retrieval_attempts", 0) < self.max_retrieval_attempts
        return "rewrite" if not enough and budget_left else "assess"

    def rewrite_queries(self, state: AgentState) -> AgentState:
        alert, previous = state["alert"], state.get("queries", [])
        try:
            queries = self.llm.generate(
                prompts.SearchQueries,
                prompts.SYSTEM_ANALYST,
                prompts.rewrite_queries_prompt(alert, previous),
            ).queries
        except Exception as exc:
            logger.warning("Query rewrite failed: %s", exc)
            queries = []
        if not queries:
            queries = [f"{alert.category.value.replace('_', ' ')} incident response playbook"]
        return {"queries": _dedupe(queries), "trace": [f"rewrite_queries: {len(queries)} new"]}

    def assess_risk(self, state: AgentState) -> AgentState:
        alert = state["alert"]
        related = state.get("related_alerts", [])
        intel = state.get("intel", [])
        baseline = heuristics.baseline_score(alert, related, intel)
        try:
            assessment = self.llm.generate(
                RiskAssessment,
                prompts.SYSTEM_ANALYST,
                prompts.assess_prompt(alert, related, state.get("context", []), baseline, intel),
            )
            # Keep the level consistent with the documented score bands.
            assessment.risk_level = heuristics.level_from_score(assessment.risk_score)
            note = f"assess_risk: score {assessment.risk_score} (heuristic {baseline})"
        except Exception as exc:
            logger.warning("Risk assessment failed: %s", exc)
            assessment = heuristics.fallback_assessment(
                alert, related, f"LLM unavailable: {type(exc).__name__}", intel
            )
            note = f"assess_risk: LLM failed, heuristic score {assessment.risk_score}"
        assessment.mitre_techniques = _dedupe(
            [*alert.mitre_techniques, *assessment.mitre_techniques]
        )
        return {"assessment": assessment, "trace": [note]}

    def recommend_actions(self, state: AgentState) -> AgentState:
        alert, assessment = state["alert"], state["assessment"]
        intel = state.get("intel", [])
        summary = (
            f"Risk {assessment.risk_score}/100 ({assessment.risk_level}). {assessment.summary}\n"
            f"Rationale: {assessment.rationale}"
        )
        try:
            recs = self.llm.generate(
                prompts.RecommendationList,
                prompts.SYSTEM_ANALYST,
                prompts.recommend_prompt(
                    alert,
                    state.get("related_alerts", []),
                    state.get("context", []),
                    summary,
                    intel,
                ),
            ).recommendations
            if not recs:
                raise ValueError("empty recommendation list")
            note = f"recommend_actions: {len(recs)} action(s)"
            # Guardrail: smaller models sometimes skip containment for serious incidents.
            serious = assessment.risk_level in (Severity.HIGH, Severity.CRITICAL)
            if serious and not any(r.phase == ResponsePhase.CONTAINMENT for r in recs):
                added = [
                    r
                    for r in heuristics.fallback_recommendations(
                        alert, assessment.risk_level, intel
                    )
                    if r.phase == ResponsePhase.CONTAINMENT
                ]
                recs = [*added, *recs]
                note += f", +{len(added)} containment step(s) added by guardrail"
        except Exception as exc:
            logger.warning("Recommendation generation failed: %s", exc)
            recs = heuristics.fallback_recommendations(alert, assessment.risk_level, intel)
            note = f"recommend_actions: LLM failed, {len(recs)} playbook default(s)"
        return {"recommendations": recs, "trace": [note]}


def _diversify(chunks: list[RetrievedChunk]) -> list[RetrievedChunk]:
    """Keep ranking order but cap chunks per document so context spans several sources."""
    per_doc: dict[str, int] = {}
    out = []
    for chunk in chunks:
        if per_doc.get(chunk.doc_id, 0) < MAX_CHUNKS_PER_DOC:
            per_doc[chunk.doc_id] = per_doc.get(chunk.doc_id, 0) + 1
            out.append(chunk)
    return out[:MAX_CONTEXT_CHUNKS]


def _default_queries(alert: NormalizedAlert) -> list[str]:
    category = alert.category.value.replace("_", " ")
    queries = [f"{alert.title} {category} triage and response"]
    if alert.description:
        queries.append(alert.description[:300])
    queries += [f"MITRE ATT&CK {t}" for t in alert.mitre_techniques[:2]]
    if alert.hostname:
        queries.append(f"asset criticality {alert.hostname}")
    return queries


def _dedupe(items):
    seen, out = set(), []
    for item in items:
        key = item.strip().lower() if isinstance(item, str) else item
        if key not in seen and key != "":
            seen.add(key)
            out.append(item)
    return out

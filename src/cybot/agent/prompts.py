"""Prompt templates and LLM output schemas for the analysis workflow."""

from __future__ import annotations

from collections.abc import Sequence

from pydantic import BaseModel, Field

from cybot.intel import IndicatorIntel
from cybot.models import Indicator, NormalizedAlert, Recommendation
from cybot.rag import RetrievedChunk

SYSTEM_ANALYST = (
    "You are a senior SOC analyst and incident responder. You analyze security alerts, "
    "use the provided knowledge-base context (playbooks, MITRE ATT&CK notes, the "
    "organization's asset inventory and policies) and correlated alerts, and give precise, "
    "evidence-based answers. Never invent facts that are not in the alert, the correlated "
    "alerts, or the context. Always answer with JSON matching the requested schema."
)


class SearchQueries(BaseModel):
    queries: list[str] = Field(
        description="2-4 short search queries for the security knowledge base", max_length=6
    )


class IndicatorSelection(BaseModel):
    selected: list[int] = Field(
        description="Numbers of the indicators most worth a threat-intel reputation lookup"
    )


class RelevanceGrades(BaseModel):
    relevant: list[int] = Field(
        description="Numbers of the documents that help assess or respond to this alert"
    )


class RecommendationList(BaseModel):
    recommendations: list[Recommendation] = Field(
        description="Ordered response actions, most urgent first", max_length=10
    )


def _related_block(related: list[NormalizedAlert]) -> str:
    if not related:
        return "None found."
    lines = []
    for a in related[:10]:
        who = ", ".join(
            f"{k}={v}"
            for k, v in (
                ("src", a.src_ip),
                ("dst", a.dst_ip),
                ("host", a.hostname),
                ("user", a.username),
            )
            if v
        )
        lines.append(
            f"- {a.timestamp.isoformat()} [{a.severity}] {a.title} "
            f"(source={a.source}, category={a.category}; {who})"
        )
    return "\n".join(lines)


def _intel_block(intel: Sequence[IndicatorIntel]) -> str:
    if not intel:
        return "No threat-intelligence lookups were performed."
    return "\n".join(f"- {i.describe()}" for i in intel)


def _context_block(chunks: list[RetrievedChunk], max_chars: int = 1200) -> str:
    if not chunks:
        return "No knowledge-base context available."
    return "\n\n".join(
        f"[{i}] {c.title} / {c.section}\n{c.text[:max_chars]}" for i, c in enumerate(chunks, 1)
    )


def select_indicators_prompt(
    alert: NormalizedAlert, candidates: Sequence[Indicator], budget: int
) -> str:
    numbered = "\n".join(f"[{n}] {i.type}: {i.value}" for n, i in enumerate(candidates, 1))
    return (
        f"You can afford at most {budget} threat-intelligence reputation lookups. Choose the "
        "indicators whose reputation would most change the risk assessment: likely attacker "
        "infrastructure (external IPs, domains, URLs) and file hashes. Skip indicators that are "
        "clearly the organization's own assets. Return their numbers, most important first.\n\n"
        f"ALERT:\n{alert.summary()}\n\nCANDIDATE INDICATORS:\n{numbered}"
    )


def plan_queries_prompt(
    alert: NormalizedAlert,
    related: list[NormalizedAlert],
    intel: Sequence[IndicatorIntel] = (),
) -> str:
    return (
        "Write search queries to retrieve the playbooks, ATT&CK techniques and asset/policy "
        "information needed to assess this alert. Include one query about the affected asset "
        "or user when known.\n\n"
        f"ALERT:\n{alert.summary()}\n\nCORRELATED ALERTS:\n{_related_block(related)}\n\n"
        f"THREAT INTELLIGENCE:\n{_intel_block(intel)}"
    )


def rewrite_queries_prompt(alert: NormalizedAlert, previous: list[str]) -> str:
    return (
        "The previous knowledge-base searches returned little relevant material. Write different, "
        "more specific queries (use technique names, tool names, or response-procedure terms).\n\n"
        f"ALERT:\n{alert.summary()}\n\nPREVIOUS QUERIES:\n" + "\n".join(f"- {q}" for q in previous)
    )


def grade_prompt(alert: NormalizedAlert, chunks: list[RetrievedChunk]) -> str:
    return (
        "Which of the numbered documents are relevant for assessing the risk of, or responding "
        "to, this alert? Return their numbers.\n\n"
        f"ALERT:\n{alert.summary()}\n\nDOCUMENTS:\n{_context_block(chunks, max_chars=600)}"
    )


def assess_prompt(
    alert: NormalizedAlert,
    related: list[NormalizedAlert],
    context: list[RetrievedChunk],
    baseline: int,
    intel: Sequence[IndicatorIntel] = (),
) -> str:
    return (
        "Assess the risk of this alert. Consider evidence of success vs. attempt, asset "
        "criticality, privileged accounts, whether correlated alerts form an attack chain, and "
        "threat-intelligence verdicts (known-malicious infrastructure or files raise the risk; "
        "an 'unknown' verdict is not evidence of safety). "
        "Use the organization's score bands (0-19 informational, 20-39 low, 40-59 medium, "
        "60-79 high, 80-100 critical). Cite context documents like [2] in the rationale. "
        f"A heuristic pre-score of {baseline}/100 was computed from severity and correlation "
        "count and intel verdicts alone; adjust it using the context.\n\n"
        f"ALERT:\n{alert.summary()}\n\n"
        f"CORRELATED ALERTS (shared indicators, +/- time window):\n{_related_block(related)}\n\n"
        f"THREAT INTELLIGENCE:\n{_intel_block(intel)}\n\n"
        f"KNOWLEDGE-BASE CONTEXT:\n{_context_block(context)}"
    )


def recommend_prompt(
    alert: NormalizedAlert,
    related: list[NormalizedAlert],
    context: list[RetrievedChunk],
    assessment_summary: str,
    intel: Sequence[IndicatorIntel] = (),
) -> str:
    return (
        "Recommend concrete response actions for this alert, following the playbooks and the "
        "escalation/approval policy in the context. Name the specific hosts, accounts, IPs, "
        "domains or hashes to act on; block indicators that threat intelligence marks "
        "malicious. Order by urgency; 3-8 actions.\n\n"
        f"ALERT:\n{alert.summary()}\n\nRISK ASSESSMENT:\n{assessment_summary}\n\n"
        f"CORRELATED ALERTS:\n{_related_block(related)}\n\n"
        f"THREAT INTELLIGENCE:\n{_intel_block(intel)}\n\n"
        f"KNOWLEDGE-BASE CONTEXT:\n{_context_block(context)}"
    )

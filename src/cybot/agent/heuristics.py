"""Deterministic scoring and response defaults.

They give the LLM a calibrated anchor and keep the service useful when the model
is unavailable or returns invalid output.
"""

from __future__ import annotations

from collections.abc import Sequence

from cybot.intel import IndicatorIntel, Verdict
from cybot.models import (
    AlertCategory,
    Likelihood,
    NormalizedAlert,
    Priority,
    Recommendation,
    ResponsePhase,
    RiskAssessment,
    Severity,
)

_SEVERITY_BASE = {
    Severity.INFORMATIONAL: 10,
    Severity.LOW: 25,
    Severity.MEDIUM: 45,
    Severity.HIGH: 65,
    Severity.CRITICAL: 80,
}
_IMPACTFUL = {
    AlertCategory.MALWARE,
    AlertCategory.COMMAND_AND_CONTROL,
    AlertCategory.DATA_EXFILTRATION,
    AlertCategory.PRIVILEGE_ESCALATION,
    AlertCategory.LATERAL_MOVEMENT,
}


def level_from_score(score: int) -> Severity:
    """Score bands from the organization's risk scoring guide."""
    if score >= 80:
        return Severity.CRITICAL
    if score >= 60:
        return Severity.HIGH
    if score >= 40:
        return Severity.MEDIUM
    if score >= 20:
        return Severity.LOW
    return Severity.INFORMATIONAL


def _flagged(intel: Sequence[IndicatorIntel], verdict: Verdict) -> list[IndicatorIntel]:
    return [i for i in intel if i.verdict == verdict]


def baseline_score(
    alert: NormalizedAlert,
    related: list[NormalizedAlert],
    intel: Sequence[IndicatorIntel] = (),
) -> int:
    score = _SEVERITY_BASE[alert.severity]
    if alert.category in _IMPACTFUL:
        score += 5
    score += min(15, 5 * len(related))
    other_categories = {a.category for a in related} - {alert.category, AlertCategory.OTHER}
    score += min(10, 5 * len(other_categories))  # multi-stage activity on shared entities
    if any(a.severity.rank > alert.severity.rank for a in related):
        score += 5
    if _flagged(intel, Verdict.MALICIOUS):
        score += 15
    elif _flagged(intel, Verdict.SUSPICIOUS):
        score += 7
    return max(0, min(100, score))


def fallback_assessment(
    alert: NormalizedAlert,
    related: list[NormalizedAlert],
    reason: str,
    intel: Sequence[IndicatorIntel] = (),
) -> RiskAssessment:
    score = baseline_score(alert, related, intel)
    rationale = (
        f"Heuristic assessment ({reason}). Base severity {alert.severity}, category "
        f"{alert.category}, {len(related)} correlated alert(s) sharing indicators."
    )
    if malicious := _flagged(intel, Verdict.MALICIOUS):
        rationale += " Threat intel marks as malicious: " + ", ".join(
            i.indicator.value for i in malicious
        )
        rationale += "."
    return RiskAssessment(
        risk_score=score,
        risk_level=level_from_score(score),
        summary=f"{alert.title} on {alert.hostname or alert.dst_ip or 'unknown asset'}",
        rationale=rationale,
        mitre_techniques=list(alert.mitre_techniques),
        confidence=0.3,
        false_positive_likelihood=Likelihood.MEDIUM,
    )


def _rec(action: str, phase: ResponsePhase, priority: Priority, rationale: str = ""):
    return Recommendation(action=action, phase=phase, priority=priority, rationale=rationale)


_CATEGORY_ACTIONS: dict[AlertCategory, list[tuple[str, ResponsePhase]]] = {
    AlertCategory.BRUTE_FORCE: [
        (
            "Check for successful logins from the source IP or for targeted accounts",
            ResponsePhase.INVESTIGATION,
        ),
        ("Block the source IP at the perimeter firewall", ResponsePhase.CONTAINMENT),
        ("Enforce key-based auth/MFA on the targeted service", ResponsePhase.PREVENTION),
    ],
    AlertCategory.MALWARE: [
        ("Isolate the affected host via EDR", ResponsePhase.CONTAINMENT),
        ("Reset credentials of accounts that logged on to the host", ResponsePhase.CONTAINMENT),
        (
            "Block the file hash organization-wide and hunt for it on other endpoints",
            ResponsePhase.ERADICATION,
        ),
        ("Reimage the host after evidence collection", ResponsePhase.RECOVERY),
    ],
    AlertCategory.COMMAND_AND_CONTROL: [
        ("Isolate the beaconing host", ResponsePhase.CONTAINMENT),
        ("Block the C2 domain/IP at DNS, proxy and firewall", ResponsePhase.CONTAINMENT),
        (
            "Search proxy/DNS logs for other hosts contacting the destination",
            ResponsePhase.INVESTIGATION,
        ),
    ],
    AlertCategory.DATA_EXFILTRATION: [
        ("Block the destination and isolate the source host", ResponsePhase.CONTAINMENT),
        ("Scope the transferred data and its classification", ResponsePhase.INVESTIGATION),
        ("Engage Legal/Privacy for breach-notification assessment", ResponsePhase.RECOVERY),
    ],
    AlertCategory.PHISHING: [
        ("Purge the message from all mailboxes and block sender/URLs", ResponsePhase.CONTAINMENT),
        (
            "Check whether recipients opened the attachment or entered credentials",
            ResponsePhase.INVESTIGATION,
        ),
        (
            "Reset credentials and revoke sessions for users who interacted",
            ResponsePhase.CONTAINMENT,
        ),
    ],
    AlertCategory.RECONNAISSANCE: [
        (
            "Check for follow-up exploitation or login attempts from the source",
            ResponsePhase.INVESTIGATION,
        ),
        ("Block persistent scanners at the perimeter", ResponsePhase.PREVENTION),
    ],
}
_DEFAULT_ACTIONS = [
    ("Validate the alert against raw logs and asset context", ResponsePhase.INVESTIGATION),
    (
        "Contain affected hosts/accounts if malicious activity is confirmed",
        ResponsePhase.CONTAINMENT,
    ),
]


def fallback_recommendations(
    alert: NormalizedAlert, risk: Severity, intel: Sequence[IndicatorIntel] = ()
) -> list[Recommendation]:
    priority = {
        Severity.CRITICAL: Priority.IMMEDIATE,
        Severity.HIGH: Priority.HIGH,
        Severity.MEDIUM: Priority.MEDIUM,
    }.get(risk, Priority.LOW)
    actions = _CATEGORY_ACTIONS.get(alert.category, _DEFAULT_ACTIONS)
    recs = [_rec(action, phase, priority, "Standard playbook step") for action, phase in actions]
    if malicious := _flagged(intel, Verdict.MALICIOUS):
        values = ", ".join(i.indicator.value for i in malicious)
        recs.insert(
            0,
            _rec(
                f"Block known-malicious indicators at perimeter/EDR: {values}",
                ResponsePhase.CONTAINMENT,
                priority,
                "Flagged malicious by threat intelligence",
            ),
        )
    return recs

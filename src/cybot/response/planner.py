"""Turn an analysis into executable, policy-checked response actions."""

from __future__ import annotations

import logging
from collections.abc import Sequence

from pydantic import BaseModel, Field

from cybot.agent.llm import StructuredLLM
from cybot.intel.providers import is_public_ip
from cybot.models import (
    AlertCategory,
    IndicatorIntel,
    IndicatorType,
    NormalizedAlert,
    Priority,
    Recommendation,
    RiskAssessment,
    Severity,
    Verdict,
)
from cybot.models.response import ActionStatus, ActionType, ApprovalMode, ResponseAction
from cybot.response.policy import ResponsePolicy

logger = logging.getLogger(__name__)

IT = IndicatorType
MAX_ACTIONS = 12

_BLOCK_FOR_TYPE = {
    IT.IP: ActionType.BLOCK_IP,
    IT.DOMAIN: ActionType.BLOCK_DOMAIN,
    IT.URL: ActionType.BLOCK_URL,
    IT.MD5: ActionType.BLOCK_HASH,
    IT.SHA1: ActionType.BLOCK_HASH,
    IT.SHA256: ActionType.BLOCK_HASH,
}
_HOST_COMPROMISE = {
    AlertCategory.MALWARE,
    AlertCategory.COMMAND_AND_CONTROL,
    AlertCategory.DATA_EXFILTRATION,
    AlertCategory.PRIVILEGE_ESCALATION,
    AlertCategory.LATERAL_MOVEMENT,
}
_CREDENTIAL_EXPOSURE = {AlertCategory.MALWARE, AlertCategory.BRUTE_FORCE, AlertCategory.PHISHING}

_CATALOG = {
    ActionType.BLOCK_IP: "block an external IP at the perimeter firewall",
    ActionType.BLOCK_DOMAIN: "block a domain at DNS/proxy",
    ActionType.BLOCK_URL: "block a URL at the web proxy",
    ActionType.BLOCK_HASH: "block a file hash on all endpoints (EDR)",
    ActionType.ISOLATE_HOST: "network-isolate a host via EDR",
    ActionType.DISABLE_ACCOUNT: "disable a user account",
    ActionType.RESET_CREDENTIALS: "force a password reset and revoke sessions for a user",
    ActionType.OPEN_TICKET: "open an incident ticket (target: short title)",
}


class ProposedAction(BaseModel):
    # Plain strings so one malformed item can be dropped without rejecting the whole list.
    type: str = Field(description="One of the action types in the catalog")
    target: str = Field(description="Exactly one of the allowed targets for that type")
    reason: str = ""
    priority: str = Field(default="medium", description="immediate | high | medium | low")


class ActionProposals(BaseModel):
    actions: list[ProposedAction] = Field(max_length=20)


def collect_targets(
    alert: NormalizedAlert,
    related: Sequence[NormalizedAlert],
    intel: Sequence[IndicatorIntel],
) -> dict[IndicatorType, dict[str, str]]:
    """Entities actions may target, by type: lowercase key -> canonical value."""
    targets: dict[IndicatorType, dict[str, str]] = {}
    indicators = [ind for a in (alert, *related) for ind in a.indicators]
    indicators += [i.indicator for i in intel]
    for ind in indicators:
        targets.setdefault(ind.type, {}).setdefault(ind.value.lower(), ind.value)
    return targets


def _priority_for(risk: Severity) -> Priority:
    return {
        Severity.CRITICAL: Priority.IMMEDIATE,
        Severity.HIGH: Priority.HIGH,
    }.get(risk, Priority.MEDIUM)


class ResponsePlanner:
    def __init__(self, llm: StructuredLLM, policy: ResponsePolicy) -> None:
        self.llm = llm
        self.policy = policy

    def plan(
        self,
        *,
        alert: NormalizedAlert,
        analysis_id: str,
        assessment: RiskAssessment,
        recommendations: Sequence[Recommendation],
        related: Sequence[NormalizedAlert] = (),
        intel: Sequence[IndicatorIntel] = (),
    ) -> tuple[list[ResponseAction], str]:
        """Return policy-evaluated actions and a short note for the workflow trace."""
        targets = collect_targets(alert, related, intel)
        try:
            proposals = self.llm.generate(
                ActionProposals,
                SYSTEM_RESPONDER,
                planning_prompt(alert, assessment, recommendations, targets),
            ).actions
            proposed, dropped = self._validate(proposals, alert, targets, assessment)
            guardrail = self._guardrail_actions(alert, assessment, intel)
            note = f"plan_response: {len(proposed)} LLM action(s)"
            if dropped:
                note += f", {dropped} invalid dropped"
        except Exception as exc:
            logger.warning("Response planning failed: %s", exc)
            proposed = []
            guardrail = self._rule_actions(alert, assessment, related, intel)
            note = f"plan_response: LLM failed, {len(guardrail)} rule-based action(s)"

        actions = self._finalize([*proposed, *guardrail], alert, analysis_id, assessment)
        added = len(actions) - len(_dedupe(proposed))
        if proposed and added > 0:
            note += f", +{added} guardrail"
        counts = {
            s: sum(a.status == s for a in actions)
            for s in (ActionStatus.APPROVED, ActionStatus.PENDING_APPROVAL, ActionStatus.DENIED)
        }
        note += (
            f" -> {counts[ActionStatus.APPROVED]} auto, "
            f"{counts[ActionStatus.PENDING_APPROVAL]} need approval, "
            f"{counts[ActionStatus.DENIED]} denied by policy"
        )
        return actions, note

    # -- proposal handling ----------------------------------------------------
    def _validate(self, proposals, alert, targets, assessment):
        valid: list[tuple[ActionType, str, str, Priority]] = []
        dropped = 0
        for p in proposals:
            try:
                atype = ActionType(p.type.strip().lower())
            except ValueError:
                dropped += 1
                continue
            if atype == ActionType.OPEN_TICKET:
                target = alert.title
            else:
                target = next(
                    (
                        targets[t][p.target.strip().lower()]
                        for t in atype.target_types
                        if p.target.strip().lower() in targets.get(t, {})
                    ),
                    None,
                )
                if target is None:  # not an entity seen in this incident
                    dropped += 1
                    continue
            try:
                priority = Priority(p.priority.strip().lower())
            except ValueError:
                priority = _priority_for(assessment.risk_level)
            valid.append((atype, target, p.reason, priority))
        return valid, dropped

    def _guardrail_actions(self, alert, assessment, intel):
        """Always block intel-confirmed malicious indicators and track serious incidents."""
        priority = _priority_for(assessment.risk_level)
        actions = [
            (
                _BLOCK_FOR_TYPE[i.indicator.type],
                i.indicator.value,
                f"Threat intel: {i.verdict} (score {i.score})",
                priority,
            )
            for i in intel
            if i.verdict == Verdict.MALICIOUS and i.indicator.type in _BLOCK_FOR_TYPE
        ]
        if assessment.risk_level.rank >= Severity.MEDIUM.rank:
            actions.append(
                (ActionType.OPEN_TICKET, alert.title, "Track the incident", Priority.MEDIUM)
            )
        return actions

    def _rule_actions(self, alert, assessment, related, intel):
        """Deterministic plan used when the model is unavailable."""
        priority = _priority_for(assessment.risk_level)
        serious = assessment.risk_level.rank >= Severity.HIGH.rank
        actions = self._guardrail_actions(alert, assessment, intel)
        if serious and alert.hostname and alert.category in _HOST_COMPROMISE:
            actions.append(
                (ActionType.ISOLATE_HOST, alert.hostname, "Contain the affected host", priority)
            )
        if serious and alert.username and alert.category in _CREDENTIAL_EXPOSURE:
            actions.append(
                (
                    ActionType.RESET_CREDENTIALS,
                    alert.username,
                    "Credentials may be compromised",
                    priority,
                )
            )
        return actions

    def _finalize(self, items, alert, analysis_id, assessment) -> list[ResponseAction]:
        actions = []
        for atype, target, reason, priority in _dedupe(items)[:MAX_ACTIONS]:
            action = ResponseAction(
                alert_id=alert.id,
                analysis_id=analysis_id,
                type=atype,
                target=target,
                reason=reason,
                priority=priority,
            )
            mode, why = self.policy.evaluate(action, assessment.risk_score)
            status = {
                ApprovalMode.AUTO: ActionStatus.APPROVED,
                ApprovalMode.REQUIRE_APPROVAL: ActionStatus.PENDING_APPROVAL,
                ApprovalMode.DENY: ActionStatus.DENIED,
            }[mode]
            actions.append(
                action.model_copy(update={"approval": mode, "policy_reason": why}).transition(
                    status, "policy", why
                )
            )
        return actions


def _dedupe(items):
    seen, out = set(), []
    for item in items:
        key = (item[0], item[1].lower())
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


SYSTEM_RESPONDER = (
    "You are an incident responder converting an analyst's recommendations into executable "
    "response actions. Only use the action types in the catalog and only the exact targets "
    "listed. Never invent hosts, accounts, IPs, domains or hashes. Answer with JSON matching "
    "the requested schema."
)


def planning_prompt(
    alert: NormalizedAlert,
    assessment: RiskAssessment,
    recommendations: Sequence[Recommendation],
    targets: dict[IndicatorType, dict[str, str]],
) -> str:
    catalog = "\n".join(f"- {t}: {desc}" for t, desc in _CATALOG.items())

    def listed(itype: IndicatorType) -> str:
        values = list(targets.get(itype, {}).values())
        if itype == IT.IP:
            values = [v if is_public_ip(v) else f"{v} (internal)" for v in values]
        return ", ".join(values) or "none"

    allowed = "\n".join(
        f"- {label}: {listed(itype)}"
        for label, itype in (
            ("hosts (isolate_host)", IT.HOST),
            ("users (disable_account, reset_credentials)", IT.USER),
            ("ips (block_ip; never block internal addresses)", IT.IP),
            ("domains (block_domain)", IT.DOMAIN),
            ("urls (block_url)", IT.URL),
            ("sha256 hashes (block_hash)", IT.SHA256),
            ("sha1 hashes (block_hash)", IT.SHA1),
            ("md5 hashes (block_hash)", IT.MD5),
        )
    )
    recs = "\n".join(f"- [{r.priority}/{r.phase}] {r.action}" for r in recommendations) or "none"
    return (
        "Convert the recommendations into executable actions (at most 10). Skip "
        "recommendations that are not in the catalog (investigation, monitoring, prevention).\n\n"
        f"ACTION CATALOG:\n{catalog}\n\nALLOWED TARGETS:\n{allowed}\n\n"
        f"ALERT:\n{alert.summary()}\n\n"
        f"RISK: {assessment.risk_score}/100 ({assessment.risk_level}). {assessment.summary}\n\n"
        f"RECOMMENDATIONS:\n{recs}"
    )

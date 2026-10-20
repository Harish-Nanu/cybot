"""Executable response actions and their approval/audit trail."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from cybot.models.alert import IndicatorType
from cybot.models.analysis import Priority


def _now() -> datetime:
    return datetime.now(UTC)


class ActionType(StrEnum):
    BLOCK_IP = "block_ip"
    BLOCK_DOMAIN = "block_domain"
    BLOCK_URL = "block_url"
    BLOCK_HASH = "block_hash"
    ISOLATE_HOST = "isolate_host"
    DISABLE_ACCOUNT = "disable_account"
    RESET_CREDENTIALS = "reset_credentials"
    OPEN_TICKET = "open_ticket"

    @property
    def disruptive(self) -> bool:
        """Whether the action changes production systems (tickets do not)."""
        return self is not ActionType.OPEN_TICKET

    @property
    def target_types(self) -> frozenset[IndicatorType]:
        """Indicator types that are valid targets for this action."""
        return _TARGET_TYPES[self]


_TARGET_TYPES = {
    ActionType.BLOCK_IP: frozenset({IndicatorType.IP}),
    ActionType.BLOCK_DOMAIN: frozenset({IndicatorType.DOMAIN}),
    ActionType.BLOCK_URL: frozenset({IndicatorType.URL}),
    ActionType.BLOCK_HASH: frozenset({IndicatorType.MD5, IndicatorType.SHA1, IndicatorType.SHA256}),
    ActionType.ISOLATE_HOST: frozenset({IndicatorType.HOST}),
    ActionType.DISABLE_ACCOUNT: frozenset({IndicatorType.USER}),
    ActionType.RESET_CREDENTIALS: frozenset({IndicatorType.USER}),
    ActionType.OPEN_TICKET: frozenset(),  # target is free text (the alert)
}


class ApprovalMode(StrEnum):
    AUTO = "auto"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


class ActionStatus(StrEnum):
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    DENIED = "denied"  # blocked by policy, never executable
    EXECUTED = "executed"
    SIMULATED = "simulated"  # dry-run: nothing was changed
    FAILED = "failed"

    @property
    def terminal(self) -> bool:
        return self in _TERMINAL


_TERMINAL = {
    ActionStatus.REJECTED,
    ActionStatus.DENIED,
    ActionStatus.EXECUTED,
    ActionStatus.SIMULATED,
    ActionStatus.FAILED,
}


class ActionEvent(BaseModel):
    """One entry in an action's audit trail."""

    at: datetime = Field(default_factory=_now)
    status: ActionStatus
    actor: str
    note: str = ""


class ResponseAction(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    alert_id: str
    analysis_id: str
    type: ActionType
    target: str
    reason: str = ""
    priority: Priority = Priority.MEDIUM
    approval: ApprovalMode = ApprovalMode.REQUIRE_APPROVAL
    policy_reason: str = ""
    status: ActionStatus = ActionStatus.PENDING_APPROVAL
    connector: str | None = None
    result: str | None = None
    created_at: datetime = Field(default_factory=_now)
    updated_at: datetime = Field(default_factory=_now)
    history: list[ActionEvent] = Field(default_factory=list)

    def transition(self, status: ActionStatus, actor: str, note: str = "") -> ResponseAction:
        """Return a copy moved to ``status`` with the change appended to the audit trail."""
        now = _now()
        event = ActionEvent(at=now, status=status, actor=actor, note=note)
        return self.model_copy(
            update={"status": status, "updated_at": now, "history": [*self.history, event]}
        )

    def describe(self) -> str:
        return f"{self.type} {self.target}"

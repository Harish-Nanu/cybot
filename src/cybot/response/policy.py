"""Approval policy: decides which response actions may run without a human."""

from __future__ import annotations

import ipaddress
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from cybot.models.response import ActionType, ApprovalMode, ResponseAction


@dataclass
class ResponsePolicy:
    default_mode: ApprovalMode = ApprovalMode.REQUIRE_APPROVAL
    action_modes: dict[ActionType, ApprovalMode] = field(default_factory=dict)
    min_auto_risk_score: int = 60
    protected_hosts: set[str] = field(default_factory=set)
    protected_accounts: set[str] = field(default_factory=set)
    never_block_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = field(
        default_factory=list
    )
    never_block_domains: set[str] = field(default_factory=set)

    @classmethod
    def load(cls, path: Path) -> ResponsePolicy:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        general = data.get("global", {})
        protected = data.get("protected", {})
        return cls(
            default_mode=ApprovalMode(general.get("default_mode", "require_approval")),
            action_modes={
                ActionType(k): ApprovalMode(v) for k, v in data.get("actions", {}).items()
            },
            min_auto_risk_score=int(general.get("min_auto_risk_score", 60)),
            protected_hosts={h.lower() for h in protected.get("hosts", [])},
            protected_accounts={a.lower() for a in protected.get("accounts", [])},
            never_block_networks=[
                ipaddress.ip_network(n, strict=False)
                for n in protected.get("never_block_networks", [])
            ],
            never_block_domains={d.lower() for d in protected.get("never_block_domains", [])},
        )

    def evaluate(self, action: ResponseAction, risk_score: int) -> tuple[ApprovalMode, str]:
        """Return the approval mode for an action and a human-readable reason."""
        target = action.target.strip().lower()
        if action.type == ActionType.BLOCK_IP and self._never_block_ip(target):
            return ApprovalMode.DENY, (
                f"{action.target} is in an internal range that must not be blocked; "
                "contain the host with isolate_host instead"
            )
        if action.type in (ActionType.BLOCK_DOMAIN, ActionType.BLOCK_URL) and (
            self._never_block_domain(target)
        ):
            return ApprovalMode.DENY, f"{action.target} belongs to a protected domain"
        if action.type == ActionType.ISOLATE_HOST and target in self.protected_hosts:
            return ApprovalMode.REQUIRE_APPROVAL, f"{action.target} is a protected asset"
        if (
            action.type in (ActionType.DISABLE_ACCOUNT, ActionType.RESET_CREDENTIALS)
            and target in self.protected_accounts
        ):
            return ApprovalMode.REQUIRE_APPROVAL, f"{action.target} is a protected account"

        mode = self.action_modes.get(action.type, self.default_mode)
        if mode == ApprovalMode.AUTO and action.type.disruptive:
            if risk_score < self.min_auto_risk_score:
                return ApprovalMode.REQUIRE_APPROVAL, (
                    f"risk {risk_score} is below the auto-response threshold "
                    f"{self.min_auto_risk_score}"
                )
            return ApprovalMode.AUTO, f"policy allows automatic {action.type}"
        if mode == ApprovalMode.AUTO:
            return ApprovalMode.AUTO, f"{action.type} is non-disruptive"
        if mode == ApprovalMode.REQUIRE_APPROVAL:
            return mode, f"policy requires approval for {action.type}"
        return mode, f"policy does not allow {action.type}"

    def _never_block_ip(self, value: str) -> bool:
        try:
            addr = ipaddress.ip_address(value)
        except ValueError:
            return False
        return any(addr in net for net in self.never_block_networks)

    def _never_block_domain(self, value: str) -> bool:
        from urllib.parse import urlparse

        host = urlparse(value).hostname if "://" in value else value
        host = (host or "").rstrip(".")
        return any(host == d or host.endswith("." + d) for d in self.never_block_domains)

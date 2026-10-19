"""Connectors that carry out approved response actions."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass

import httpx

from cybot.models.response import ActionStatus, ResponseAction

logger = logging.getLogger(__name__)


@dataclass
class ExecutionOutcome:
    status: ActionStatus  # EXECUTED, SIMULATED or FAILED
    detail: str


class ActionConnector(ABC):
    name: str

    def execute(self, action: ResponseAction) -> ExecutionOutcome:
        """Carry out an action. Never raises: failures are reported as FAILED."""
        try:
            return self._execute(action)
        except Exception as exc:
            logger.exception("Connector %s failed for action %s", self.name, action.id)
            return ExecutionOutcome(ActionStatus.FAILED, f"{type(exc).__name__}: {exc}")

    @abstractmethod
    def _execute(self, action: ResponseAction) -> ExecutionOutcome: ...


class SimulatedConnector(ActionConnector):
    """Dry run: records what would have been done without touching any system."""

    name = "simulated"

    def _execute(self, action: ResponseAction) -> ExecutionOutcome:
        return ExecutionOutcome(ActionStatus.SIMULATED, f"dry run: would {action.describe()}")


def sign(secret: str, timestamp: str, body: bytes) -> str:
    digest = hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256)
    return "sha256=" + digest.hexdigest()


def verify_signature(
    secret: str,
    timestamp: str,
    body: bytes,
    signature: str,
    *,
    tolerance_seconds: int = 300,
    now: float | None = None,
) -> bool:
    """Receiver-side check of ``X-Cybot-Signature`` (rejects stale timestamps to stop replays)."""
    try:
        age = abs((now if now is not None else time.time()) - int(timestamp))
    except ValueError:
        return False
    return age <= tolerance_seconds and hmac.compare_digest(
        sign(secret, timestamp, body), signature
    )


class WebhookConnector(ActionConnector):
    """POSTs each action as JSON to a SOAR/automation endpoint (Tines, n8n, Shuffle, XSOAR...).

    Headers: ``X-Cybot-Event``, ``X-Cybot-Delivery`` (action id, usable as an idempotency
    key), ``X-Cybot-Timestamp`` and ``X-Cybot-Signature`` (HMAC-SHA256 of
    ``"{timestamp}.{body}"`` when a secret is configured).
    """

    name = "webhook"

    def __init__(
        self,
        url: str,
        secret: str | None = None,
        *,
        timeout: float = 10.0,
        client: httpx.Client | None = None,
    ) -> None:
        self.url = url
        self._secret = secret
        self._client = client or httpx.Client(timeout=timeout)

    def _execute(self, action: ResponseAction) -> ExecutionOutcome:
        timestamp = str(int(time.time()))
        payload = {
            "event": "cybot.response_action",
            "action": action.model_dump(mode="json", exclude={"history"}),
        }
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        headers = {
            "Content-Type": "application/json",
            "X-Cybot-Event": "response_action",
            "X-Cybot-Delivery": action.id,
            "X-Cybot-Timestamp": timestamp,
        }
        if self._secret:
            headers["X-Cybot-Signature"] = sign(self._secret, timestamp, body)

        try:
            resp = self._client.post(self.url, content=body, headers=headers)
        except httpx.HTTPError as exc:
            return ExecutionOutcome(ActionStatus.FAILED, f"webhook unreachable: {exc}")
        snippet = resp.text[:200].strip()
        detail = f"HTTP {resp.status_code}" + (f": {snippet}" if snippet else "")
        if resp.is_success:
            return ExecutionOutcome(ActionStatus.EXECUTED, detail)
        return ExecutionOutcome(ActionStatus.FAILED, detail)


def build_connector(settings) -> ActionConnector:
    if settings.response_mode == "dry_run":
        return SimulatedConnector()
    if not settings.response_webhook_url:
        raise ValueError("CYBOT_RESPONSE_MODE=live requires CYBOT_RESPONSE_WEBHOOK_URL")
    secret = settings.response_webhook_secret
    return WebhookConnector(
        settings.response_webhook_url,
        secret.get_secret_value() if secret else None,
        timeout=settings.response_timeout_seconds,
    )

import json
import time

import httpx
import pytest
from pydantic import SecretStr

from cybot.config import Settings
from cybot.models import ActionStatus, ActionType, ResponseAction
from cybot.response import (
    SimulatedConnector,
    WebhookConnector,
    build_connector,
    verify_signature,
)

ACTION = ResponseAction(
    alert_id="alert-1",
    analysis_id="analysis-1",
    type=ActionType.BLOCK_DOMAIN,
    target="update-cdn-sync.net",
    reason="C2 domain",
)


def client_for(handler):
    seen = []

    def _handle(request):
        seen.append(request)
        return handler(request)

    client = httpx.Client(transport=httpx.MockTransport(_handle))
    client.seen = seen
    return client


def test_simulated_connector():
    outcome = SimulatedConnector().execute(ACTION)
    assert outcome.status == ActionStatus.SIMULATED
    assert outcome.detail == "dry run: would block_domain update-cdn-sync.net"


def test_webhook_posts_signed_payload():
    client = client_for(lambda r: httpx.Response(202, text="queued"))
    outcome = WebhookConnector("https://soar.example/hook", "s3cret", client=client).execute(ACTION)
    assert outcome.status == ActionStatus.EXECUTED
    assert outcome.detail == "HTTP 202: queued"

    (req,) = client.seen
    body = req.content
    payload = json.loads(body)
    assert payload["event"] == "cybot.response_action"
    assert payload["action"]["target"] == "update-cdn-sync.net"
    assert "history" not in payload["action"]
    assert req.headers["X-Cybot-Delivery"] == ACTION.id
    ts, sig = req.headers["X-Cybot-Timestamp"], req.headers["X-Cybot-Signature"]
    assert verify_signature("s3cret", ts, body, sig)
    assert not verify_signature("wrong", ts, body, sig)
    assert not verify_signature("s3cret", ts, body + b" ", sig)
    # Replays outside the tolerance window are rejected.
    assert not verify_signature("s3cret", ts, body, sig, now=time.time() + 3600)


def test_webhook_without_secret_is_unsigned():
    client = client_for(lambda r: httpx.Response(200))
    WebhookConnector("https://soar.example/hook", client=client).execute(ACTION)
    assert "X-Cybot-Signature" not in client.seen[0].headers


@pytest.mark.parametrize(
    ("handler", "fragment"),
    [
        (lambda r: httpx.Response(500, text="boom"), "HTTP 500: boom"),
        (lambda r: (_ for _ in ()).throw(httpx.ConnectError("refused")), "webhook unreachable"),
    ],
)
def test_webhook_failures_are_reported(handler, fragment):
    outcome = WebhookConnector("https://x", client=client_for(handler)).execute(ACTION)
    assert outcome.status == ActionStatus.FAILED
    assert fragment in outcome.detail


def test_build_connector():
    assert build_connector(Settings()).name == "simulated"
    live = Settings(
        response_mode="live",
        response_webhook_url="https://soar.example/hook",
        response_webhook_secret=SecretStr("k"),
    )
    assert build_connector(live).name == "webhook"
    with pytest.raises(ValueError, match="RESPONSE_WEBHOOK_URL"):
        build_connector(Settings(response_mode="live"))

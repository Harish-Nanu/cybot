from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from cybot.agent import Decision, DecisionError
from cybot.api.alerts import get_alert_or_404
from cybot.api.deps import ServicesDep
from cybot.models import ActionStatus, ResponseAction

router = APIRouter(tags=["response"])


class DecisionIn(BaseModel):
    action_id: str
    approve: bool
    note: str = Field(default="", max_length=2000)


class DecisionsRequest(BaseModel):
    analyst: str = Field(min_length=1, max_length=200, description="Who is deciding (audit)")
    decisions: list[DecisionIn] = Field(min_length=1)


class DecisionsResponse(BaseModel):
    analysis_id: str
    awaiting_approval: bool
    actions: list[ResponseAction]
    trace: list[str]


@router.get("/actions", response_model=list[ResponseAction])
def list_actions(
    services: ServicesDep,
    status_: Annotated[ActionStatus | None, Query(alias="status")] = None,
    alert_id: str | None = None,
    analysis_id: str | None = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 200,
) -> list[ResponseAction]:
    """Response actions with their audit trail; `?status=pending_approval` is the approval queue."""
    return services.repo.list_actions(
        alert_id=alert_id, analysis_id=analysis_id, status=status_, limit=limit
    )


@router.get("/actions/{action_id}", response_model=ResponseAction)
def get_action(action_id: str, services: ServicesDep) -> ResponseAction:
    action = services.repo.get_action(action_id)
    if action is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Action not found")
    return action


@router.get("/alerts/{alert_id}/actions", response_model=list[ResponseAction])
def alert_actions(alert_id: str, services: ServicesDep) -> list[ResponseAction]:
    get_alert_or_404(services, alert_id)
    return services.repo.list_actions(alert_id=alert_id)


@router.post("/analyses/{analysis_id}/decisions", response_model=DecisionsResponse)
def decide(analysis_id: str, request: DecisionsRequest, services: ServicesDep) -> DecisionsResponse:
    """Approve or reject pending actions of a paused analysis; approved actions then run."""
    try:
        trace = services.analyzer.decide(
            analysis_id,
            [Decision(d.action_id, d.approve, d.note) for d in request.decisions],
            request.analyst,
        )
    except DecisionError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from None
    return DecisionsResponse(
        analysis_id=analysis_id,
        awaiting_approval=services.analyzer.is_waiting(analysis_id),
        actions=services.repo.list_actions(analysis_id=analysis_id),
        trace=trace,
    )

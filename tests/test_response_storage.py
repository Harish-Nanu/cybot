from cybot.models import ActionStatus, ActionType, ResponseAction


def make(alert_id, analysis_id="an-1", atype=ActionType.BLOCK_IP, target="8.8.8.8"):
    return ResponseAction(alert_id=alert_id, analysis_id=analysis_id, type=atype, target=target)


def test_save_update_and_audit_trail(repo, sample_alerts):
    repo.add_alerts(sample_alerts)
    alert_id = sample_alerts[0].id
    action = make(alert_id)
    repo.save_actions([action])
    assert repo.get_action(action.id) == action

    approved = action.transition(ActionStatus.APPROVED, "alice", "ok")
    done = approved.transition(ActionStatus.SIMULATED, "connector:simulated", "dry run")
    repo.save_actions([done])
    loaded = repo.get_action(action.id)
    assert loaded.status == ActionStatus.SIMULATED
    assert [(e.status, e.actor) for e in loaded.history] == [
        (ActionStatus.APPROVED, "alice"),
        (ActionStatus.SIMULATED, "connector:simulated"),
    ]
    assert repo.get_action("missing") is None


def test_list_actions_filters(repo, sample_alerts):
    repo.add_alerts(sample_alerts)
    a1, a2 = sample_alerts[0].id, sample_alerts[1].id
    pending = make(a1, "an-1")
    other = make(a1, "an-1", ActionType.OPEN_TICKET, "ticket").transition(
        ActionStatus.SIMULATED, "system"
    )
    elsewhere = make(a2, "an-2")
    repo.save_actions([pending, other, elsewhere])

    assert {a.id for a in repo.list_actions(alert_id=a1)} == {pending.id, other.id}
    assert [a.id for a in repo.list_actions(analysis_id="an-2")] == [elsewhere.id]
    pending_ids = {a.id for a in repo.list_actions(status=ActionStatus.PENDING_APPROVAL)}
    assert pending_ids == {pending.id, elsewhere.id}

from datetime import timedelta

from cybot.models import (
    AlertCategory,
    AnalysisResult,
    RiskAssessment,
    Severity,
)


def by_title(alerts, fragment):
    return next(a for a in alerts if fragment in a.title)


def test_add_and_get_roundtrip(repo, sample_alerts):
    repo.add_alerts(sample_alerts)
    original = sample_alerts[0]
    loaded = repo.get_alert(original.id)
    assert loaded == original
    assert loaded.timestamp.tzinfo is not None
    assert repo.get_alert("missing") is None


def test_list_filters_and_pagination(repo, sample_alerts):
    repo.add_alerts(sample_alerts)
    alerts, total = repo.list_alerts()
    assert total == len(sample_alerts)
    assert alerts == sorted(alerts, key=lambda a: a.timestamp, reverse=True)

    high, _ = repo.list_alerts(min_severity=Severity.HIGH)
    assert high and all(a.severity.rank >= Severity.HIGH.rank for a in high)

    wazuh, total_wazuh = repo.list_alerts(source="wazuh")
    assert total_wazuh == 2 and {a.source for a in wazuh} == {"wazuh"}

    page, total = repo.list_alerts(limit=2, offset=1)
    assert len(page) == 2 and total == len(sample_alerts)

    phishing, _ = repo.list_alerts(category=AlertCategory.PHISHING)
    assert [a.source for a in phishing] == ["generic"]


def test_find_related_by_shared_indicators(repo, sample_alerts):
    repo.add_alerts(sample_alerts)
    brute = by_title(sample_alerts, "brute force")
    related_titles = {a.title for a in repo.find_related(brute)}
    # Same attacker IP / host: SSH scan and the later successful login.
    assert "ET SCAN Potential SSH Scan" in related_titles
    assert "sshd: authentication success." in related_titles
    assert brute.title not in related_titles

    dumping = by_title(sample_alerts, "Credential Dumping")
    related = {a.source for a in repo.find_related(dumping)}
    # WS-FIN-07 / j.doe / 10.0.2.57 link EDR, beacon, exfil and phishing alerts.
    assert {"suricata", "splunk", "generic"} <= related


def test_find_related_respects_time_window(repo, sample_alerts):
    brute = by_title(sample_alerts, "brute force")
    later = brute.model_copy(
        update={"id": "later", "timestamp": brute.timestamp + timedelta(days=3)}
    )
    repo.add_alerts([brute, later])
    assert repo.find_related(brute, window_hours=24) == []
    assert [a.id for a in repo.find_related(brute, window_hours=24 * 7)] == ["later"]


def test_analysis_persistence(repo, sample_alerts):
    repo.add_alerts(sample_alerts)
    alert = sample_alerts[0]
    result = AnalysisResult(
        alert_id=alert.id,
        assessment=RiskAssessment(
            risk_score=82, risk_level=Severity.HIGH, summary="s", rationale="r"
        ),
    )
    repo.save_analysis(result)
    assert repo.latest_analysis(alert.id) == result
    assert repo.high_risk_analyses(min_score=80) == [result]
    assert repo.high_risk_analyses(min_score=90) == []

import json
from pathlib import Path

import pytest

from cybot.ingestion.normalizers import (
    NORMALIZERS,
    NormalizationError,
    UnknownSourceError,
    get_normalizer,
)
from cybot.models import AlertCategory, IndicatorType, Severity

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def load(source):
    return json.loads((SAMPLES / f"{source}.json").read_text())


def iocs(alert, itype):
    return {i.value for i in alert.indicators if i.type == itype}


@pytest.mark.parametrize("source", sorted(NORMALIZERS))
def test_all_samples_normalize(source):
    for payload in load(source):
        alert = get_normalizer(source).normalize(payload)
        assert alert.source == source
        assert alert.title
        assert alert.raw == payload


def test_suricata():
    scan, beacon = (get_normalizer("suricata").normalize(p) for p in load("suricata"))
    assert scan.severity == Severity.MEDIUM
    assert scan.category == AlertCategory.RECONNAISSANCE
    assert (scan.src_ip, scan.dst_ip, scan.dst_port) == ("203.0.113.45", "10.0.1.20", 22)
    assert scan.mitre_techniques == ["T1046"]
    assert beacon.severity == Severity.HIGH
    assert beacon.category == AlertCategory.COMMAND_AND_CONTROL
    assert "update-cdn-sync.net" in iocs(beacon, IndicatorType.DOMAIN)


def test_wazuh():
    brute, success = (get_normalizer("wazuh").normalize(p) for p in load("wazuh"))
    assert brute.severity == Severity.HIGH
    assert brute.category == AlertCategory.BRUTE_FORCE
    assert brute.src_ip == "203.0.113.45"
    assert brute.hostname == "web-srv-01"
    assert brute.username == "admin"
    assert success.severity == Severity.INFORMATIONAL
    assert success.username == "deploy"


def test_crowdstrike():
    (alert,) = (get_normalizer("crowdstrike").normalize(p) for p in load("crowdstrike"))
    assert alert.severity == Severity.CRITICAL
    assert alert.category == AlertCategory.MALWARE
    assert alert.hostname == "WS-FIN-07"
    assert alert.mitre_techniques == ["T1003.001"]
    assert iocs(alert, IndicatorType.SHA256)
    assert not iocs(alert, IndicatorType.MD5)  # zero-padded hash dropped
    assert alert.timestamp.year == 2026


def test_splunk():
    (alert,) = (get_normalizer("splunk").normalize(p) for p in load("splunk"))
    assert alert.severity == Severity.HIGH
    assert alert.category == AlertCategory.DATA_EXFILTRATION
    assert (alert.src_ip, alert.dst_ip, alert.dst_port) == ("10.0.2.57", "198.51.100.77", 443)


def test_generic():
    (alert,) = (get_normalizer("generic").normalize(p) for p in load("generic"))
    assert alert.category == AlertCategory.PHISHING
    assert "billing@invoices-secure-pay.com" in iocs(alert, IndicatorType.EMAIL)
    assert "http://invoices-secure-pay.com/view.php" in iocs(alert, IndicatorType.URL)


def test_generic_requires_title():
    with pytest.raises(NormalizationError):
        get_normalizer("generic").normalize({"severity": "high"})


@pytest.mark.parametrize("source", ["suricata", "wazuh", "crowdstrike", "splunk"])
def test_vendor_normalizers_reject_foreign_payloads(source):
    with pytest.raises(NormalizationError):
        get_normalizer(source).normalize({"title": "not my format"})


def test_unknown_source():
    with pytest.raises(UnknownSourceError):
        get_normalizer("nope")

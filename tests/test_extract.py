from datetime import UTC, datetime

from cybot.ingestion.extract import (
    dig,
    extract_indicators,
    first,
    infer_category,
    parse_timestamp,
)
from cybot.models import AlertCategory, IndicatorType, Severity


def _by_type(indicators):
    out = {}
    for ind in indicators:
        out.setdefault(ind.type, []).append(ind.value)
    return out


def test_extract_indicators_mixed_text():
    sha = "a" * 64
    text = (
        f"Download from http://evil.example.com/payload.exe by 10.0.0.5 to 203.0.113.9, "
        f"hash {sha} md5 {'b' * 32}; mail from attacker@bad-domain.org; dropped invoice.exe"
    )
    found = _by_type(extract_indicators([text]))
    assert found[IndicatorType.URL] == ["http://evil.example.com/payload.exe"]
    assert set(found[IndicatorType.IP]) == {"10.0.0.5", "203.0.113.9"}
    assert found[IndicatorType.SHA256] == [sha]
    assert found[IndicatorType.MD5] == ["b" * 32]
    assert found[IndicatorType.EMAIL] == ["attacker@bad-domain.org"]
    # File names must not be mistaken for domains; URL/email hosts are not duplicated.
    assert IndicatorType.DOMAIN not in found


def test_extract_ignores_invalid_ips_and_dedupes():
    found = extract_indicators(["999.1.1.1 and 8.8.8.8 and 8.8.8.8", None])
    assert [(i.type, i.value) for i in found] == [(IndicatorType.IP, "8.8.8.8")]


def test_infer_category():
    assert infer_category("SSH brute force attempt") == AlertCategory.BRUTE_FORCE
    assert infer_category("Nmap scan detected") == AlertCategory.RECONNAISSANCE
    assert infer_category("Mimikatz credential dumping") == AlertCategory.MALWARE
    assert infer_category("something odd") == AlertCategory.OTHER


def test_dig_and_first():
    data = {"a": {"b": {"c": 1}}, "x": ""}
    assert dig(data, "a.b.c") == 1
    assert dig(data, "a.z") is None
    assert first(data, "x", "a.b.c") == 1


def test_parse_timestamp_formats():
    assert parse_timestamp("2024-05-01T10:00:00.123456+0000") == datetime(
        2024, 5, 1, 10, 0, 0, 123456, tzinfo=UTC
    )
    assert parse_timestamp("2024-05-01T10:00:00Z").tzinfo is not None
    assert parse_timestamp(1714557600000) == datetime(2024, 5, 1, 10, 0, tzinfo=UTC)
    assert parse_timestamp("1714557600") == datetime(2024, 5, 1, 10, 0, tzinfo=UTC)


def test_severity_parse():
    assert Severity.parse("CRIT") == Severity.CRITICAL
    assert Severity.parse("unknown", default=Severity.LOW) == Severity.LOW
    assert Severity.HIGH.rank > Severity.LOW.rank


def test_infer_category_uses_word_boundaries():
    # "rce" inside "source" and "tor" inside "monitor" must not trigger categories.
    assert infer_category("monitor source changed") == AlertCategory.OTHER
    assert infer_category("Outbound TOR connection") == AlertCategory.POLICY_VIOLATION

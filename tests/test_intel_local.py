import pytest

from cybot.ingestion.extract import detect_indicator_type
from cybot.intel import IndicatorIntel, IntelResult, Verdict
from cybot.intel.providers import LocalIntelProvider, is_public_ip
from cybot.models import Indicator, IndicatorType
from tests.conftest import INTEL_FILE

IT = IndicatorType


@pytest.fixture(scope="module")
def local():
    return LocalIntelProvider(INTEL_FILE)


def lookup(provider, itype, value):
    return provider.lookup(Indicator(type=itype, value=value))


def test_exact_and_case_insensitive_match(local):
    r = lookup(local, IT.DOMAIN, "Update-CDN-Sync.net")
    assert (r.verdict, r.score, r.provider) == (Verdict.MALICIOUS, 95, "local")
    assert "cobaltstrike" in r.tags


def test_cidr_match_and_exact_precedence(local):
    assert lookup(local, IT.IP, "203.0.113.45").verdict == Verdict.MALICIOUS
    assert lookup(local, IT.IP, "203.0.113.200").verdict == Verdict.SUSPICIOUS
    assert lookup(local, IT.IP, "192.0.2.1").verdict == Verdict.UNKNOWN


def test_subdomain_url_and_email_match_parent_domain(local):
    assert lookup(local, IT.DOMAIN, "a.b.update-cdn-sync.net").verdict == Verdict.MALICIOUS
    r = lookup(local, IT.URL, "http://invoices-secure-pay.com/view.php")
    assert r.verdict == Verdict.MALICIOUS
    assert lookup(local, IT.EMAIL, "billing@invoices-secure-pay.com").verdict == Verdict.MALICIOUS
    assert lookup(local, IT.EMAIL, "j.doe@corp.example").verdict == Verdict.HARMLESS


def test_never_matches_bare_tld(local):
    assert lookup(local, IT.DOMAIN, "other.net").verdict == Verdict.UNKNOWN


def test_supports(local):
    assert local.supports(Indicator(type=IT.IP, value="10.0.0.1"))  # private IPs allowed locally
    assert not local.supports(Indicator(type=IT.USER, value="j.doe"))


def test_is_public_ip():
    assert is_public_ip("8.8.8.8")
    assert not is_public_ip("10.0.0.1")
    assert not is_public_ip("203.0.113.45")  # documentation range
    assert not is_public_ip("not-an-ip")


def test_aggregate_precedence():
    ind = Indicator(type=IT.IP, value="8.8.8.8")

    def res(verdict, score=0, error=None):
        return IntelResult(
            provider="p",
            indicator_type=IT.IP,
            value="8.8.8.8",
            verdict=verdict,
            score=score,
            error=error,
        )

    agg = IndicatorIntel.aggregate(ind, [res(Verdict.HARMLESS), res(Verdict.SUSPICIOUS, 40)])
    assert (agg.verdict, agg.score) == (Verdict.SUSPICIOUS, 40)
    agg = IndicatorIntel.aggregate(ind, [res(Verdict.UNKNOWN), res(Verdict.HARMLESS)])
    assert agg.verdict == Verdict.HARMLESS
    # Errors don't count toward the verdict but are reported.
    agg = IndicatorIntel.aggregate(ind, [res(Verdict.MALICIOUS, 99, error="timeout")])
    assert (agg.verdict, agg.score) == (Verdict.UNKNOWN, 0)
    assert "lookup failed: p" in agg.describe()


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("8.8.8.8", IT.IP),
        ("https://evil.example.com/x", IT.URL),
        ("a@b.com", IT.EMAIL),
        ("d41d8cd98f00b204e9800998ecf8427e", IT.MD5),
        ("a" * 40, IT.SHA1),
        ("b" * 64, IT.SHA256),
        ("evil.example.com", IT.DOMAIN),
        ("not an ioc", None),
    ],
)
def test_detect_indicator_type(value, expected):
    assert detect_indicator_type(value) == expected

import base64
import json

import httpx
import pytest
from pydantic import SecretStr

from cybot.config import Settings
from cybot.intel import Verdict
from cybot.intel.providers import (
    AbuseIPDBProvider,
    GreyNoiseProvider,
    URLhausProvider,
    VirusTotalProvider,
    build_providers,
)
from cybot.models import Indicator, IndicatorType

IT = IndicatorType


def mock_client(handler):
    """httpx client whose requests are answered by ``handler`` (records requests)."""
    requests = []

    def _handle(request):
        requests.append(request)
        return handler(request)

    client = httpx.Client(transport=httpx.MockTransport(_handle))
    client.requests = requests
    return client


def json_response(data, status=200):
    return lambda request: httpx.Response(status, json=data)


IP = Indicator(type=IT.IP, value="8.8.4.4")


def test_abuseipdb_malicious():
    client = mock_client(
        json_response(
            {
                "data": {
                    "abuseConfidenceScore": 100,
                    "totalReports": 512,
                    "countryCode": "NL",
                    "isp": "Bad Hosting",
                    "isTor": True,
                }
            }
        )
    )
    r = AbuseIPDBProvider("k", client=client).lookup(IP)
    assert (r.verdict, r.score) == (Verdict.MALICIOUS, 100)
    assert "512 report(s)" in r.summary and r.tags == ["tor"]
    req = client.requests[0]
    assert req.headers["Key"] == "k"
    assert req.url.params["ipAddress"] == "8.8.4.4"


@pytest.mark.parametrize(
    ("score", "whitelisted", "verdict"),
    [(50, False, Verdict.SUSPICIOUS), (0, True, Verdict.HARMLESS), (0, False, Verdict.UNKNOWN)],
)
def test_abuseipdb_thresholds(score, whitelisted, verdict):
    body = {"data": {"abuseConfidenceScore": score, "isWhitelisted": whitelisted}}
    r = AbuseIPDBProvider("k", client=mock_client(json_response(body))).lookup(IP)
    assert r.verdict == verdict


def vt_body(malicious, suspicious=0, harmless=60, undetected=10, **attrs):
    stats = {
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
    }
    return {"data": {"attributes": {"last_analysis_stats": stats, **attrs}}}


def test_virustotal_file_hash():
    body = vt_body(
        55,
        harmless=0,
        undetected=15,
        tags=["peexe"],
        popular_threat_classification={"suggested_threat_label": "hacktool.mimikatz"},
    )
    client = mock_client(json_response(body))
    sha = "a" * 64
    r = VirusTotalProvider("vt", client=client).lookup(Indicator(type=IT.SHA256, value=sha))
    assert r.verdict == Verdict.MALICIOUS and r.score == 100
    assert "hacktool.mimikatz" in r.summary
    assert client.requests[0].url.path == f"/api/v3/files/{sha}"
    assert client.requests[0].headers["x-apikey"] == "vt"


def test_virustotal_url_id_is_unpadded_base64():
    client = mock_client(json_response(vt_body(0)))
    url = "http://evil.example.com/a"
    r = VirusTotalProvider("vt", client=client).lookup(Indicator(type=IT.URL, value=url))
    expected_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    assert client.requests[0].url.path == f"/api/v3/urls/{expected_id}"
    assert r.verdict == Verdict.HARMLESS


def test_virustotal_suspicious_and_not_found():
    r = VirusTotalProvider("vt", client=mock_client(json_response(vt_body(1)))).lookup(IP)
    assert r.verdict == Verdict.SUSPICIOUS
    r = VirusTotalProvider("vt", client=mock_client(json_response({}, 404))).lookup(IP)
    assert r.verdict == Verdict.UNKNOWN and r.error is None


@pytest.mark.parametrize(
    ("body", "verdict"),
    [
        ({"noise": True, "riot": False, "classification": "malicious"}, Verdict.MALICIOUS),
        (
            {"noise": False, "riot": True, "classification": "benign", "name": "Google"},
            Verdict.HARMLESS,
        ),
        ({"noise": True, "riot": False, "classification": "unknown"}, Verdict.SUSPICIOUS),
    ],
)
def test_greynoise(body, verdict):
    client = mock_client(json_response(body))
    r = GreyNoiseProvider("gn", client=client).lookup(IP)
    assert r.verdict == verdict
    assert client.requests[0].headers["key"] == "gn"


def test_greynoise_not_observed():
    r = GreyNoiseProvider("gn", client=mock_client(json_response({}, 404))).lookup(IP)
    assert r.verdict == Verdict.UNKNOWN and r.error is None


def test_urlhaus_url_and_payload_and_no_results():
    def handler(request):
        form = dict(x.split("=") for x in request.content.decode().split("&"))
        assert request.headers["Auth-Key"] == "uh"
        if request.url.path == "/v1/url/":
            return httpx.Response(
                200,
                json={
                    "query_status": "ok",
                    "threat": "malware_download",
                    "url_status": "online",
                    "tags": ["emotet"],
                    "urlhaus_reference": "https://urlhaus.abuse.ch/url/1/",
                },
            )
        if request.url.path == "/v1/payload/":
            assert "sha256_hash" in form
            return httpx.Response(
                200, json={"query_status": "ok", "signature": "Emotet", "file_type": "exe"}
            )
        return httpx.Response(200, json={"query_status": "no_results"})

    provider = URLhausProvider("uh", client=mock_client(handler))
    r = provider.lookup(Indicator(type=IT.URL, value="http://x.example.com/a"))
    assert (r.verdict, r.score, r.tags) == (Verdict.MALICIOUS, 95, ["emotet"])
    r = provider.lookup(Indicator(type=IT.SHA256, value="c" * 64))
    assert r.verdict == Verdict.MALICIOUS and "Emotet" in r.summary
    r = provider.lookup(Indicator(type=IT.DOMAIN, value="clean.example.com"))
    assert r.verdict == Verdict.UNKNOWN


def test_rate_limit_and_network_errors_are_reported_not_raised():
    r = AbuseIPDBProvider("k", client=mock_client(json_response({}, 429))).lookup(IP)
    assert r.error == "rate limited"

    def boom(request):
        raise httpx.ConnectTimeout("timed out")

    r = VirusTotalProvider("vt", client=mock_client(boom)).lookup(IP)
    assert r.error and "ConnectTimeout" in r.error


def test_remote_providers_skip_non_public_ips():
    provider = AbuseIPDBProvider("k", client=mock_client(json_response({})))
    assert provider.supports(IP)
    assert not provider.supports(Indicator(type=IT.IP, value="10.0.0.1"))
    assert not provider.supports(Indicator(type=IT.DOMAIN, value="example.com"))


def test_build_providers_enables_only_configured(tmp_path):
    settings = Settings(
        intel_local_path=tmp_path / "missing.csv",
        virustotal_api_key=SecretStr("vt"),
        greynoise_api_key=SecretStr(""),
    )
    assert [p.name for p in build_providers(settings)] == ["virustotal"]
    assert "vt" not in repr(settings)  # keys are not leaked in reprs/logs
    assert json.dumps(settings.model_dump(mode="json")).count('"vt"') == 0

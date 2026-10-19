"""Online reputation services. Each is enabled only when its API key is configured."""

from __future__ import annotations

import base64
from typing import Any

import httpx

from cybot.intel.models import IntelResult, Verdict
from cybot.intel.providers.base import IntelProvider
from cybot.models.alert import Indicator, IndicatorType

IT = IndicatorType


class HttpIntelProvider(IntelProvider):
    def __init__(
        self, api_key: str, *, timeout: float = 10.0, client: httpx.Client | None = None
    ) -> None:
        self._api_key = api_key
        self._client = client or httpx.Client(timeout=timeout)


class AbuseIPDBProvider(HttpIntelProvider):
    """https://docs.abuseipdb.com/#check-endpoint"""

    name = "abuseipdb"
    supported_types = frozenset({IT.IP})
    url = "https://api.abuseipdb.com/api/v2/check"

    def _lookup(self, indicator: Indicator) -> IntelResult:
        resp = self._client.get(
            self.url,
            params={"ipAddress": indicator.value, "maxAgeInDays": 90},
            headers={"Key": self._api_key, "Accept": "application/json"},
        )
        resp.raise_for_status()
        data = resp.json()["data"]
        score = int(data.get("abuseConfidenceScore") or 0)
        reports = int(data.get("totalReports") or 0)
        if score >= 75:
            verdict = Verdict.MALICIOUS
        elif score >= 25:
            verdict = Verdict.SUSPICIOUS
        elif data.get("isWhitelisted"):
            verdict = Verdict.HARMLESS
        else:
            verdict = Verdict.UNKNOWN
        details = [f"confidence {score}%", f"{reports} report(s)"]
        details += [str(data[k]) for k in ("countryCode", "isp", "usageType") if data.get(k)]
        tags = ["tor"] if data.get("isTor") else []
        return self._result(
            indicator,
            verdict,
            score,
            summary=", ".join(details),
            tags=tags,
            reference=f"https://www.abuseipdb.com/check/{indicator.value}",
        )


class VirusTotalProvider(HttpIntelProvider):
    """https://docs.virustotal.com/reference/overview (API v3)"""

    name = "virustotal"
    supported_types = frozenset({IT.IP, IT.DOMAIN, IT.URL, IT.MD5, IT.SHA1, IT.SHA256})
    base_url = "https://www.virustotal.com/api/v3"
    _collections = {
        IT.IP: ("ip_addresses", "ip-address"),
        IT.DOMAIN: ("domains", "domain"),
        IT.URL: ("urls", "url"),
        IT.MD5: ("files", "file"),
        IT.SHA1: ("files", "file"),
        IT.SHA256: ("files", "file"),
    }

    def _lookup(self, indicator: Indicator) -> IntelResult:
        collection, gui = self._collections[indicator.type]
        object_id = (
            base64.urlsafe_b64encode(indicator.value.encode()).decode().rstrip("=")
            if indicator.type == IT.URL
            else indicator.value
        )
        resp = self._client.get(
            f"{self.base_url}/{collection}/{object_id}", headers={"x-apikey": self._api_key}
        )
        if resp.status_code == 404:
            return self._result(indicator, Verdict.UNKNOWN, summary="not found in VirusTotal")
        resp.raise_for_status()
        attrs: dict[str, Any] = resp.json()["data"]["attributes"]
        stats = attrs.get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))
        engines = sum(int(v) for v in stats.values()) or 1

        if malicious >= 3:
            verdict = Verdict.MALICIOUS
        elif malicious >= 1 or suspicious >= 2:
            verdict = Verdict.SUSPICIOUS
        elif harmless > 0:
            verdict = Verdict.HARMLESS
        else:
            verdict = Verdict.UNKNOWN
        # Detection ratios rarely exceed ~70%, so scale up to use the full 0-100 range.
        score = round(min(1.0, (malicious + 0.5 * suspicious) / engines * 1.5) * 100)

        summary = f"{malicious}/{engines} engines malicious, {suspicious} suspicious"
        label = (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label")
        if label:
            summary += f", label {label}"
        return self._result(
            indicator,
            verdict,
            score,
            summary=summary,
            tags=[str(t) for t in attrs.get("tags", [])][:10],
            reference=f"https://www.virustotal.com/gui/{gui}/{object_id}",
        )


class GreyNoiseProvider(HttpIntelProvider):
    """https://docs.greynoise.io/reference/get_v3-community-ip (Community API)"""

    name = "greynoise"
    supported_types = frozenset({IT.IP})
    base_url = "https://api.greynoise.io/v3/community"

    def _lookup(self, indicator: Indicator) -> IntelResult:
        resp = self._client.get(
            f"{self.base_url}/{indicator.value}",
            headers={"key": self._api_key, "Accept": "application/json"},
        )
        if resp.status_code == 404:  # not observed scanning and not a known benign service
            return self._result(indicator, Verdict.UNKNOWN, summary="not observed by GreyNoise")
        resp.raise_for_status()
        data = resp.json()
        classification = str(data.get("classification") or "unknown").lower()
        if classification == "malicious":
            verdict, score = Verdict.MALICIOUS, 80
        elif classification == "benign" or data.get("riot"):
            verdict, score = Verdict.HARMLESS, 0
        elif data.get("noise"):
            verdict, score = Verdict.SUSPICIOUS, 40  # mass-scanning the internet
        else:
            verdict, score = Verdict.UNKNOWN, 0
        details = [f"classification {classification}"]
        if data.get("noise"):
            details.append("internet scanner")
        if data.get("riot"):
            details.append("known business service")
        if data.get("name") and data["name"] != "unknown":
            details.append(str(data["name"]))
        return self._result(
            indicator,
            verdict,
            score,
            summary=", ".join(details),
            reference=data.get("link"),
        )


class URLhausProvider(HttpIntelProvider):
    """https://urlhaus-api.abuse.ch/ (malware distribution URLs, hosts and payloads)"""

    name = "urlhaus"
    supported_types = frozenset({IT.URL, IT.DOMAIN, IT.IP, IT.MD5, IT.SHA256})
    base_url = "https://urlhaus-api.abuse.ch/v1"

    def _lookup(self, indicator: Indicator) -> IntelResult:
        if indicator.type == IT.URL:
            endpoint, form = "url", {"url": indicator.value}
        elif indicator.type in (IT.DOMAIN, IT.IP):
            endpoint, form = "host", {"host": indicator.value}
        else:
            key = "md5_hash" if indicator.type == IT.MD5 else "sha256_hash"
            endpoint, form = "payload", {key: indicator.value}

        resp = self._client.post(
            f"{self.base_url}/{endpoint}/", data=form, headers={"Auth-Key": self._api_key}
        )
        resp.raise_for_status()
        data = resp.json()
        status = data.get("query_status")
        if status != "ok":
            return self._result(indicator, Verdict.UNKNOWN, summary=f"URLhaus: {status}")

        if endpoint == "url":
            summary = f"{data.get('threat', 'malware')} URL, status {data.get('url_status')}"
            score = 95 if data.get("url_status") == "online" else 80
        elif endpoint == "host":
            summary = f"host served {data.get('url_count', '?')} malware URL(s)"
            score = 80
        else:
            summary = f"malware payload {data.get('signature') or ''} ({data.get('file_type')})"
            score = 90
        return self._result(
            indicator,
            Verdict.MALICIOUS,
            score,
            summary=summary.strip(),
            tags=[str(t) for t in (data.get("tags") or [])][:10],
            reference=data.get("urlhaus_reference"),
        )

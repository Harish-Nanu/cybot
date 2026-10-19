from collections.abc import Mapping
from typing import Any

from cybot.ingestion.extract import as_list, dig, infer_category, parse_timestamp, to_int
from cybot.ingestion.normalizers.base import NormalizationError, Normalizer
from cybot.models.alert import Indicator, IndicatorType, NormalizedAlert, Severity

# Suricata priorities: 1 is the most severe.
_SEVERITY = {1: Severity.HIGH, 2: Severity.MEDIUM, 3: Severity.LOW, 4: Severity.INFORMATIONAL}


class SuricataNormalizer(Normalizer):
    """Suricata EVE JSON ``event_type: alert`` records."""

    source = "suricata"
    description = "Suricata IDS EVE JSON alert events"

    def _normalize(self, payload: Mapping[str, Any]) -> NormalizedAlert:
        alert = payload.get("alert")
        if not isinstance(alert, Mapping) or not alert.get("signature"):
            raise NormalizationError("suricata: expected an EVE record with alert.signature")

        signature = str(alert["signature"])
        category_label = alert.get("category")
        metadata = alert.get("metadata") or {}
        mitre = [str(t) for t in as_list(metadata.get("mitre_technique_id"))]

        indicators = []
        if http_host := dig(payload, "http.hostname"):
            indicators.append(Indicator(type=IndicatorType.DOMAIN, value=str(http_host)))
            url = dig(payload, "http.url")
            if url:
                indicators.append(Indicator(type=IndicatorType.URL, value=f"{http_host}{url}"))
        if dns_name := dig(payload, "dns.rrname"):
            indicators.append(Indicator(type=IndicatorType.DOMAIN, value=str(dns_name)))

        return NormalizedAlert(
            source=self.source,
            source_alert_id=_event_id(payload, alert),
            title=signature,
            description=f"Suricata rule {alert.get('signature_id')}: {category_label}"
            if category_label
            else None,
            severity=_SEVERITY.get(to_int(alert.get("severity")) or 2, Severity.MEDIUM),
            category=infer_category(signature, category_label),
            timestamp=parse_timestamp(payload.get("timestamp")),
            src_ip=payload.get("src_ip"),
            src_port=to_int(payload.get("src_port")),
            dst_ip=payload.get("dest_ip"),
            dst_port=to_int(payload.get("dest_port")),
            protocol=payload.get("proto"),
            hostname=payload.get("host") or payload.get("in_iface"),
            indicators=indicators,
            mitre_techniques=mitre,
            tags=["ids", "network"] + [str(c) for c in as_list(category_label)],
            raw=dict(payload),
        )


def _event_id(payload: Mapping[str, Any], alert: Mapping[str, Any]) -> str | None:
    # A flow can trigger several signatures, so the pair identifies one alert event.
    flow_id = payload.get("flow_id")
    return f"{flow_id}:{alert.get('signature_id')}" if flow_id else None

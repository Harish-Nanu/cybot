from collections.abc import Mapping
from typing import Any

from cybot.ingestion.extract import as_list, first, infer_category, parse_timestamp, to_int
from cybot.ingestion.normalizers.base import NormalizationError, Normalizer
from cybot.models.alert import NormalizedAlert, Severity


class SplunkNormalizer(Normalizer):
    """Splunk alert-action webhook payloads (``{"search_name": ..., "result": {...}}``)."""

    source = "splunk"
    description = "Splunk saved-search / ES notable event webhook"

    def _normalize(self, payload: Mapping[str, Any]) -> NormalizedAlert:
        result = payload.get("result")
        if not isinstance(result, Mapping):
            raise NormalizationError("splunk: expected a webhook payload with a 'result' object")

        title = first(result, "rule_name", "signature", "search_name") or payload.get("search_name")
        if not title:
            raise NormalizationError("splunk: could not determine alert name")
        description = first(result, "rule_description", "description", "_raw")

        return NormalizedAlert(
            source=self.source,
            source_alert_id=str(first(result, "event_id", "notable_id") or payload.get("sid") or "")
            or None,
            title=str(title),
            description=str(description) if description else None,
            severity=Severity.parse(first(result, "urgency", "severity", "priority")),
            category=infer_category(str(title), str(description or ""), result.get("category")),
            timestamp=parse_timestamp(first(result, "_time", "timestamp")),
            src_ip=first(result, "src_ip", "src"),
            src_port=to_int(first(result, "src_port")),
            dst_ip=first(result, "dest_ip", "dest", "dst"),
            dst_port=to_int(first(result, "dest_port", "dst_port")),
            protocol=first(result, "transport", "protocol"),
            hostname=first(result, "host", "dest_host", "dvc"),
            username=first(result, "user", "src_user"),
            mitre_techniques=[
                str(t)
                for t in as_list(first(result, "annotations.mitre_attack", "mitre_technique_id"))
            ],
            tags=[str(t) for t in as_list(result.get("tag"))],
            raw=dict(payload),
        )

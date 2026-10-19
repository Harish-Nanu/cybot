from collections.abc import Mapping
from typing import Any

from cybot.ingestion.extract import as_list, first, infer_category, parse_timestamp, to_int
from cybot.ingestion.normalizers.base import NormalizationError, Normalizer
from cybot.models.alert import AlertCategory, Indicator, IndicatorType, NormalizedAlert, Severity


class GenericNormalizer(Normalizer):
    """Lenient mapper for custom tools/webhooks using common field names."""

    source = "generic"
    description = "Any JSON alert with common field names (title/name, severity, src_ip, ...)"

    def _normalize(self, payload: Mapping[str, Any]) -> NormalizedAlert:
        title = first(payload, "title", "name", "rule_name", "signature", "message", "summary")
        if not title:
            raise NormalizationError("generic: alert needs a title/name/message field")
        description = first(payload, "description", "details", "message")
        category_raw = first(payload, "category", "type")
        try:
            category = AlertCategory(str(category_raw).lower())
        except ValueError:
            category = infer_category(title, description, category_raw)

        indicators = []
        for item in as_list(payload.get("indicators")):
            if isinstance(item, Mapping) and item.get("type") and item.get("value"):
                try:
                    indicators.append(
                        Indicator(type=IndicatorType(item["type"]), value=str(item["value"]))
                    )
                except ValueError:
                    continue

        return NormalizedAlert(
            source=str(payload.get("source") or self.source),
            source_alert_id=_str(first(payload, "id", "alert_id", "event_id")),
            title=str(title),
            description=_str(description) if description != title else None,
            severity=Severity.parse(first(payload, "severity", "priority", "level")),
            category=category,
            timestamp=parse_timestamp(first(payload, "timestamp", "time", "@timestamp")),
            src_ip=first(payload, "src_ip", "source_ip", "src", "source.ip"),
            src_port=to_int(first(payload, "src_port", "source_port", "source.port")),
            dst_ip=first(payload, "dst_ip", "dest_ip", "destination_ip", "dst", "destination.ip"),
            dst_port=to_int(first(payload, "dst_port", "dest_port", "destination.port")),
            protocol=first(payload, "protocol", "proto"),
            hostname=first(payload, "hostname", "host", "host.name", "computer"),
            username=first(payload, "username", "user", "user.name"),
            indicators=indicators,
            mitre_techniques=[str(t) for t in as_list(first(payload, "mitre_techniques", "mitre"))],
            tags=[str(t) for t in as_list(payload.get("tags"))],
            raw=dict(payload),
        )


def _str(value: Any) -> str | None:
    return None if value is None else str(value)

from collections.abc import Mapping
from typing import Any

from cybot.ingestion.extract import as_list, first, infer_category, parse_timestamp, to_int
from cybot.ingestion.normalizers.base import NormalizationError, Normalizer
from cybot.models.alert import NormalizedAlert, Severity


def _level_to_severity(level: int | None) -> Severity:
    # Wazuh rule levels range 0-15.
    if level is None:
        return Severity.MEDIUM
    if level <= 3:
        return Severity.INFORMATIONAL
    if level <= 6:
        return Severity.LOW
    if level <= 9:
        return Severity.MEDIUM
    if level <= 12:
        return Severity.HIGH
    return Severity.CRITICAL


class WazuhNormalizer(Normalizer):
    """Wazuh manager alerts (alerts.json / integration webhook)."""

    source = "wazuh"
    description = "Wazuh HIDS/SIEM alerts (rule.level 0-15)"

    def _normalize(self, payload: Mapping[str, Any]) -> NormalizedAlert:
        rule = payload.get("rule")
        if not isinstance(rule, Mapping) or not rule.get("description"):
            raise NormalizationError("wazuh: expected an alert with rule.description")

        title = str(rule["description"])
        groups = [str(g) for g in as_list(rule.get("groups"))]
        full_log = payload.get("full_log")
        return NormalizedAlert(
            source=self.source,
            source_alert_id=str(payload["id"]) if payload.get("id") else None,
            title=title,
            description=full_log,
            severity=_level_to_severity(to_int(rule.get("level"))),
            category=infer_category(title, " ".join(groups)),
            timestamp=parse_timestamp(payload.get("timestamp")),
            src_ip=first(payload, "data.srcip", "data.src_ip"),
            src_port=to_int(first(payload, "data.srcport", "data.src_port")),
            dst_ip=first(payload, "data.dstip", "data.dst_ip", "agent.ip"),
            dst_port=to_int(first(payload, "data.dstport", "data.dst_port")),
            protocol=first(payload, "data.protocol"),
            hostname=first(payload, "agent.name", "manager.name"),
            username=first(
                payload, "data.dstuser", "data.srcuser", "data.win.eventdata.targetUserName"
            ),
            mitre_techniques=[str(t) for t in as_list(first(payload, "rule.mitre.id"))],
            tags=groups,
            raw=dict(payload),
        )

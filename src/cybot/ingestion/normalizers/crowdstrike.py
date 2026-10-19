from collections.abc import Mapping
from typing import Any

from cybot.ingestion.extract import as_list, infer_category, parse_timestamp, to_int
from cybot.ingestion.normalizers.base import NormalizationError, Normalizer
from cybot.models.alert import Indicator, IndicatorType, NormalizedAlert, Severity

_SEVERITY = {
    1: Severity.INFORMATIONAL,
    2: Severity.LOW,
    3: Severity.MEDIUM,
    4: Severity.HIGH,
    5: Severity.CRITICAL,
}


class CrowdStrikeNormalizer(Normalizer):
    """CrowdStrike Falcon streaming API ``DetectionSummaryEvent``."""

    source = "crowdstrike"
    description = "CrowdStrike Falcon EDR DetectionSummaryEvent (Severity 1-5)"

    def _normalize(self, payload: Mapping[str, Any]) -> NormalizedAlert:
        event = payload.get("event", payload)
        if not isinstance(event, Mapping) or not (
            event.get("DetectName") or event.get("DetectDescription")
        ):
            raise NormalizationError("crowdstrike: expected event.DetectName/DetectDescription")

        title = str(event.get("DetectName") or event.get("DetectDescription"))
        tactic, technique = event.get("Tactic"), event.get("Technique")
        severity = _SEVERITY.get(to_int(event.get("Severity")) or 0) or Severity.parse(
            event.get("SeverityName")
        )

        indicators: list[Indicator] = []
        for field, itype in (
            ("SHA256String", IndicatorType.SHA256),
            ("SHA1String", IndicatorType.SHA1),
            ("MD5String", IndicatorType.MD5),
            ("FilePath", IndicatorType.FILE_PATH),
            ("FileName", IndicatorType.PROCESS),
        ):
            value = event.get(field)
            if value and set(str(value)) != {"0"}:  # Falcon pads missing hashes with zeros
                indicators.append(Indicator(type=itype, value=str(value)))

        description_parts = [
            event.get("DetectDescription"),
            f"Command line: {event['CommandLine']}" if event.get("CommandLine") else None,
            f"Tactic/Technique: {tactic} / {technique}" if tactic or technique else None,
        ]
        return NormalizedAlert(
            source=self.source,
            source_alert_id=event.get("DetectId"),
            title=title,
            description="\n".join(p for p in description_parts if p) or None,
            severity=severity,
            category=infer_category(title, tactic, technique, event.get("DetectDescription")),
            timestamp=parse_timestamp(
                event.get("ProcessStartTime")
                or (payload.get("metadata") or {}).get("eventCreationTime")
            ),
            src_ip=event.get("LocalIP"),
            hostname=event.get("ComputerName"),
            username=event.get("UserName"),
            indicators=indicators,
            mitre_techniques=[str(t) for t in as_list(event.get("TechniqueId"))],
            tags=["edr"] + [str(t) for t in (tactic, technique) if t],
            raw=dict(payload),
        )

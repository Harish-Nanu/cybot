"""Registry of supported alert sources."""

from cybot.ingestion.normalizers.base import NormalizationError, Normalizer
from cybot.ingestion.normalizers.crowdstrike import CrowdStrikeNormalizer
from cybot.ingestion.normalizers.generic import GenericNormalizer
from cybot.ingestion.normalizers.splunk import SplunkNormalizer
from cybot.ingestion.normalizers.suricata import SuricataNormalizer
from cybot.ingestion.normalizers.wazuh import WazuhNormalizer

NORMALIZERS: dict[str, Normalizer] = {
    n.source: n
    for n in (
        GenericNormalizer(),
        SuricataNormalizer(),
        WazuhNormalizer(),
        CrowdStrikeNormalizer(),
        SplunkNormalizer(),
    )
}


class UnknownSourceError(KeyError):
    pass


def get_normalizer(source: str) -> Normalizer:
    try:
        return NORMALIZERS[source.lower()]
    except KeyError as exc:
        raise UnknownSourceError(source) from exc


__all__ = [
    "NORMALIZERS",
    "NormalizationError",
    "Normalizer",
    "UnknownSourceError",
    "get_normalizer",
]

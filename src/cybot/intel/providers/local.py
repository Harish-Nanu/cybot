"""Offline provider backed by a CSV of known indicators (internal blocklists, past incidents)."""

from __future__ import annotations

import csv
import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from cybot.intel.providers.base import IntelProvider
from cybot.models.alert import Indicator, IndicatorType
from cybot.models.intel import IntelResult, Verdict


@dataclass
class _Entry:
    verdict: Verdict
    score: int
    description: str
    tags: list[str] = field(default_factory=list)


class LocalIntelProvider(IntelProvider):
    """CSV columns: type,value,verdict,score,description,tags (tags separated by ``|``).

    ``type`` is an indicator type or ``cidr`` for IP ranges. Domain entries also match
    subdomains and URLs on that host.
    """

    name = "local"
    supported_types = frozenset(
        {
            IndicatorType.IP,
            IndicatorType.DOMAIN,
            IndicatorType.URL,
            IndicatorType.EMAIL,
            IndicatorType.MD5,
            IndicatorType.SHA1,
            IndicatorType.SHA256,
        }
    )
    requires_public_ip = False
    cacheable = False

    def __init__(self, path: Path) -> None:
        self.path = path
        self._exact: dict[tuple[str, str], _Entry] = {}
        self._networks: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, _Entry]] = []
        self._load()

    def __len__(self) -> int:
        return len(self._exact) + len(self._networks)

    def _load(self) -> None:
        with self.path.open(newline="", encoding="utf-8") as fh:
            rows = csv.DictReader(line for line in fh if line.strip() and not line.startswith("#"))
            for row in rows:
                entry = _Entry(
                    verdict=Verdict(row["verdict"].strip().lower()),
                    score=int(row.get("score") or 0),
                    description=(row.get("description") or "").strip(),
                    tags=[t for t in (row.get("tags") or "").split("|") if t],
                )
                kind, value = row["type"].strip().lower(), row["value"].strip().lower()
                if kind == "cidr":
                    self._networks.append((ipaddress.ip_network(value, strict=False), entry))
                else:
                    self._exact[(IndicatorType(kind).value, value)] = entry

    def _lookup(self, indicator: Indicator) -> IntelResult:
        entry = self._match(indicator.type, indicator.value.lower())
        if entry is None:
            return self._result(indicator, Verdict.UNKNOWN, summary="not in local intel")
        return self._result(
            indicator, entry.verdict, entry.score, summary=entry.description, tags=entry.tags
        )

    def _match(self, itype: IndicatorType, value: str) -> _Entry | None:
        if entry := self._exact.get((itype.value, value)):
            return entry
        if itype == IndicatorType.IP:
            addr = ipaddress.ip_address(value)
            return next((e for net, e in self._networks if addr in net), None)
        if itype == IndicatorType.DOMAIN:
            labels = value.split(".")
            for i in range(1, len(labels) - 1):  # parent domains, never the bare TLD
                if entry := self._exact.get((IndicatorType.DOMAIN.value, ".".join(labels[i:]))):
                    return entry
        if itype == IndicatorType.URL:
            host = urlparse(value).hostname or ""
            if host:
                return self._match(IndicatorType.DOMAIN, host)
        if itype == IndicatorType.EMAIL and "@" in value:
            return self._match(IndicatorType.DOMAIN, value.rsplit("@", 1)[1])
        return None

"""Common, source-agnostic alert schema that every integration normalizes into."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class Severity(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return list(Severity).index(self)

    @classmethod
    def parse(cls, value: Any, default: Severity | None = None) -> Severity:
        """Best-effort conversion of free-form severity labels."""
        if isinstance(value, Severity):
            return value
        if value is None:
            return default or cls.MEDIUM
        text = str(value).strip().lower()
        aliases = {
            "info": cls.INFORMATIONAL,
            "informational": cls.INFORMATIONAL,
            "information": cls.INFORMATIONAL,
            "none": cls.INFORMATIONAL,
            "low": cls.LOW,
            "medium": cls.MEDIUM,
            "moderate": cls.MEDIUM,
            "med": cls.MEDIUM,
            "high": cls.HIGH,
            "critical": cls.CRITICAL,
            "crit": cls.CRITICAL,
            "severe": cls.CRITICAL,
        }
        return aliases.get(text, default or cls.MEDIUM)


class AlertCategory(StrEnum):
    MALWARE = "malware"
    INTRUSION = "intrusion"
    BRUTE_FORCE = "brute_force"
    RECONNAISSANCE = "reconnaissance"
    PHISHING = "phishing"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    COMMAND_AND_CONTROL = "command_and_control"
    POLICY_VIOLATION = "policy_violation"
    OTHER = "other"


class IndicatorType(StrEnum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    FILE_PATH = "file_path"
    PROCESS = "process"
    USER = "user"
    HOST = "host"


class Indicator(BaseModel):
    type: IndicatorType
    value: str

    @field_validator("value")
    @classmethod
    def _strip(cls, v: str) -> str:
        return v.strip()


def _utcnow() -> datetime:
    return datetime.now(UTC)


class NormalizedAlert(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source: str
    source_alert_id: str | None = None
    title: str
    description: str | None = None
    severity: Severity = Severity.MEDIUM
    category: AlertCategory = AlertCategory.OTHER
    timestamp: datetime = Field(default_factory=_utcnow)
    ingested_at: datetime = Field(default_factory=_utcnow)

    src_ip: str | None = None
    src_port: int | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    protocol: str | None = None
    hostname: str | None = None
    username: str | None = None

    indicators: list[Indicator] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp", "ingested_at")
    @classmethod
    def _ensure_utc(cls, v: datetime) -> datetime:
        return v.replace(tzinfo=UTC) if v.tzinfo is None else v.astimezone(UTC)

    def summary(self) -> str:
        """Compact, human-readable description used in prompts and logs."""
        parts = [f"[{self.severity.upper()}] {self.title} (source={self.source})"]
        if self.description:
            parts.append(f"Description: {self.description}")
        net = []
        if self.src_ip:
            net.append(f"src={self.src_ip}" + (f":{self.src_port}" if self.src_port else ""))
        if self.dst_ip:
            net.append(f"dst={self.dst_ip}" + (f":{self.dst_port}" if self.dst_port else ""))
        if self.protocol:
            net.append(f"proto={self.protocol}")
        if net:
            parts.append("Network: " + " ".join(net))
        if self.hostname or self.username:
            parts.append(f"Host: {self.hostname or '-'}  User: {self.username or '-'}")
        parts.append(f"Category: {self.category}  Time: {self.timestamp.isoformat()}")
        if self.mitre_techniques:
            parts.append("MITRE: " + ", ".join(self.mitre_techniques))
        if self.indicators:
            iocs = ", ".join(f"{i.type}:{i.value}" for i in self.indicators[:20])
            parts.append(f"Indicators: {iocs}")
        return "\n".join(parts)

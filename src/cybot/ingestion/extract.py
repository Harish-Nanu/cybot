"""Helpers shared by normalizers: IOC extraction, category inference, field access."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from typing import Any

from cybot.models.alert import AlertCategory, Indicator, IndicatorType

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_URL_RE = re.compile(r"\bhttps?://[^\s\"'<>]+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,24})\b", re.IGNORECASE
)
_HASH_RES = {
    IndicatorType.SHA256: re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE),
    IndicatorType.SHA1: re.compile(r"\b[a-f0-9]{40}\b", re.IGNORECASE),
    IndicatorType.MD5: re.compile(r"\b[a-f0-9]{32}\b", re.IGNORECASE),
}
# File extensions that the domain regex would otherwise pick up (e.g. "invoice.exe").
_NOT_TLDS = {
    "exe", "dll", "bat", "ps1", "sh", "py", "js", "vbs", "txt", "log", "doc", "docx",
    "xls", "xlsx", "pdf", "zip", "rar", "tmp", "dat", "bin", "conf", "json", "xml",
    "html", "htm", "php", "jsp", "asp", "aspx", "png", "jpg", "gif", "lnk", "msi", "iso",
    "docm", "xlsm", "ppt", "pptx", "rtf", "hta", "scr", "jar", "gz", "tar", "cab", "elf", "so",
}  # fmt: skip


def is_valid_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def extract_indicators(texts: Iterable[str | None]) -> list[Indicator]:
    """Pull IOCs (IPs, URLs, emails, domains, hashes) out of free text."""
    found: list[Indicator] = []
    for text in texts:
        if not text:
            continue
        for url in _URL_RE.findall(text):
            found.append(Indicator(type=IndicatorType.URL, value=url.rstrip(".,;)")))
        for email in _EMAIL_RE.findall(text):
            found.append(Indicator(type=IndicatorType.EMAIL, value=email))
        for ip in _IPV4_RE.findall(text):
            if is_valid_ip(ip):
                found.append(Indicator(type=IndicatorType.IP, value=ip))
        stripped = _URL_RE.sub(" ", _EMAIL_RE.sub(" ", text))
        for domain in _DOMAIN_RE.findall(stripped):
            if domain.rsplit(".", 1)[-1].lower() not in _NOT_TLDS and not is_valid_ip(domain):
                found.append(Indicator(type=IndicatorType.DOMAIN, value=domain.lower()))
        remaining = text
        for itype, regex in _HASH_RES.items():  # longest first so substrings aren't re-matched
            for h in regex.findall(remaining):
                found.append(Indicator(type=itype, value=h.lower()))
            remaining = regex.sub(" ", remaining)
    return dedupe_indicators(found)


def dedupe_indicators(indicators: Iterable[Indicator]) -> list[Indicator]:
    seen: set[tuple[str, str]] = set()
    out: list[Indicator] = []
    for ind in indicators:
        key = (ind.type.value, ind.value.lower())
        if ind.value and key not in seen:
            seen.add(key)
            out.append(ind)
    return out


_CATEGORY_KEYWORDS: list[tuple[AlertCategory, tuple[str, ...]]] = [
    (
        AlertCategory.BRUTE_FORCE,
        (
            "brute",
            "password spray",
            "multiple failed",
            "authentication failure",
            "failed login",
            "failed password",
        ),
    ),
    (
        AlertCategory.PHISHING,
        ("phish", "malicious attachment", "credential harvest", "spoofed sender"),
    ),
    (AlertCategory.DATA_EXFILTRATION, ("exfil", "data transfer", "large upload", "dns tunnel")),
    (
        AlertCategory.PRIVILEGE_ESCALATION,
        ("privilege escalation", "privesc", "sudo", "uac bypass", "token manipulation"),
    ),
    (
        AlertCategory.LATERAL_MOVEMENT,
        ("lateral", "psexec", "pass the hash", "pass-the-hash", "wmi remote", "remote service"),
    ),
    (
        AlertCategory.COMMAND_AND_CONTROL,
        (r"c2\b", "command and control", "command-and-control", "beacon", "cobalt strike"),
    ),
    (
        AlertCategory.MALWARE,
        (
            "malware",
            "trojan",
            "ransomware",
            "virus",
            "worm",
            "backdoor",
            "mimikatz",
            "credential dump",
            "malicious file",
        ),
    ),
    (AlertCategory.RECONNAISSANCE, ("scan", "recon", "nmap", "enumeration", "discovery", "sweep")),
    (
        AlertCategory.INTRUSION,
        ("exploit", "injection", "intrusion", r"rce\b", "attack", "shellcode", "web attack"),
    ),
    (
        AlertCategory.POLICY_VIOLATION,
        ("policy", "unauthorized software", r"tor\b", "p2p", "compliance"),
    ),
]

_CATEGORY_PATTERNS = [
    (category, re.compile(r"\b(?:" + "|".join(keywords) + ")", re.IGNORECASE))
    for category, keywords in _CATEGORY_KEYWORDS
]


def infer_category(*texts: str | None) -> AlertCategory:
    """Keyword-based category guess; keywords match at word starts ("phish" ~ "phishing")."""
    haystack = " ".join(t for t in texts if t)
    for category, pattern in _CATEGORY_PATTERNS:
        if pattern.search(haystack):
            return category
    return AlertCategory.OTHER


def dig(data: Mapping[str, Any], path: str, default: Any = None) -> Any:
    """Read a dotted path from nested dicts: dig(d, "alert.signature")."""
    current: Any = data
    for key in path.split("."):
        if not isinstance(current, Mapping) or key not in current:
            return default
        current = current[key]
    return current


def first(data: Mapping[str, Any], *paths: str, default: Any = None) -> Any:
    """Return the first non-empty value among several dotted paths."""
    for path in paths:
        value = dig(data, path)
        if value not in (None, "", [], {}):
            return value
    return default


def parse_timestamp(value: Any) -> datetime:
    """Parse ISO-8601 strings, epoch seconds/milliseconds; falls back to now (UTC)."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, int | float) or (isinstance(value, str) and _is_number(value)):
        num = float(value)
        if num > 1e12:  # milliseconds
            num /= 1000
        return datetime.fromtimestamp(num, tz=UTC)
    if isinstance(value, str) and value:
        text = value.strip().replace("Z", "+00:00")
        # Suricata/Wazuh emit "+0000" offsets, which fromisoformat accepts on 3.11+.
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return datetime.now(UTC)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    return datetime.now(UTC)


def _is_number(text: str) -> bool:
    try:
        float(text)
    except ValueError:
        return False
    return True


def to_int(value: Any) -> int | None:
    try:
        return int(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]

"""
WebOSINT Pro - risk roll-up.

Most plugins still report through the legacy dict API: they write values into
self.findings and tag risks with set_risk(), which stores _risk_<name> keys.
Only newer plugins call report() and populate the normalized collector.

The summary has to consider both, otherwise a scan can show 78 findings while
every severity bucket reads zero. This module converts the legacy risk markers
into normalized finding rows and counts them.
"""

from __future__ import annotations

from typing import Any

RISK_PREFIX = "_risk_"
SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_ORDER = {name: index for index, name in enumerate(SEVERITIES)}

TITLE_OVERRIDES = {
    "missing_headers": "Missing security headers",
    "header_disclosure": "Information disclosure via headers",
    "no_spf": "No SPF record",
    "no_dmarc": "No DMARC record",
    "no_dkim": "No DKIM record",
    "email_spoofing": "Email spoofing possible",
    "sensitive_paths": "Sensitive paths exposed",
    "backup_files": "Backup files exposed",
    "dangerous_ports": "Dangerous ports exposed",
    "weak_ciphers": "Weak TLS ciphers",
    "expired_cert": "Expired TLS certificate",
    "no_dnssec": "DNSSEC not enabled",
    "directory_listing": "Directory listing enabled",
}


def normalize_severity(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text in SEVERITY_ORDER:
        return text
    if text in ("warn", "warning", "moderate"):
        return "medium"
    if text in ("severe", "crit"):
        return "critical"
    return "info"


def humanize(key: str) -> str:
    if key in TITLE_OVERRIDES:
        return TITLE_OVERRIDES[key]
    return key.replace("_", " ").strip().capitalize()


def summarize_value(value: Any, limit: int = 240) -> str:
    """Render a finding value compactly for table display."""
    if value in (None, "", [], {}):
        return ""
    if isinstance(value, list):
        parts = [item if isinstance(item, str) else summarize_value(item, 80) for item in value]
        text = "; ".join(part for part in parts if part)
    elif isinstance(value, dict):
        pairs = []
        for key, item in value.items():
            if item in (None, "", [], {}):
                continue
            pairs.append(str(key) + "=" + summarize_value(item, 60))
        text = "; ".join(pairs)
    else:
        text = str(value)
    text = " ".join(text.split())
    if len(text) > limit:
        return text[: limit - 1] + "..."
    return text


def derive_legacy_findings(findings_by_module: dict[str, Any]) -> list[dict[str, Any]]:
    """Build normalized rows from _risk_ markers in the legacy findings dict."""
    rows: list[dict[str, Any]] = []
    if not isinstance(findings_by_module, dict):
        return rows

    for module, data in findings_by_module.items():
        if not isinstance(data, dict):
            continue
        for key, level in data.items():
            name = str(key)
            if not name.startswith(RISK_PREFIX):
                continue
            subject = name[len(RISK_PREFIX) :]
            rows.append(
                {
                    "module": str(module),
                    "category": "risk",
                    "title": humanize(subject),
                    "value": summarize_value(data.get(subject, "")),
                    "severity": normalize_severity(level),
                    "confidence": 0.6,
                    "status": "unverified",
                    "sources": [str(module)],
                    "evidence": "",
                    "origin": "legacy_risk_marker",
                }
            )
    return rows


def count_severities(rows: list[dict[str, Any]]) -> dict[str, int]:
    counts = dict.fromkeys(SEVERITIES, 0)
    for row in rows:
        counts[normalize_severity(row.get("severity"))] += 1
    return counts


def sort_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deterministic order: severity first, then module and title."""
    return sorted(
        rows,
        key=lambda row: (
            SEVERITY_ORDER.get(normalize_severity(row.get("severity")), 9),
            str(row.get("module", "")),
            str(row.get("title", "")),
        ),
    )


def merge_findings(
    normalized: list[dict[str, Any]],
    legacy: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Combine collector rows with legacy rows, dropping duplicate titles."""
    merged: list[dict[str, Any]] = list(normalized or [])
    seen = set()
    for row in merged:
        seen.add((str(row.get("module", "")).lower(), str(row.get("title", "")).lower()))
    for row in legacy:
        key = (str(row.get("module", "")).lower(), str(row.get("title", "")).lower())
        if key in seen:
            continue
        seen.add(key)
        merged.append(row)
    return sort_rows(merged)

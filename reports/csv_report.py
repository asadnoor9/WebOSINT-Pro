"""
WebOSINT Pro - CSV report generator

One row per finding, deterministically ordered, spreadsheet friendly.
Values are already redacted by the controller before they reach a report.
"""

from __future__ import annotations

import csv
from typing import Any

COLUMNS = [
    "target",
    "module",
    "category",
    "title",
    "value",
    "severity",
    "confidence",
    "status",
    "sources",
    "evidence",
]


class CSVReport:
    def __init__(self, results: dict[str, Any]):
        self.results = results

    def _rows(self) -> list[dict[str, Any]]:
        meta = self.results.get("meta", {})
        target = meta.get("target", "")
        rows: list[dict[str, Any]] = []

        # Prefer the normalized, deduplicated findings when present.
        normalized = self.results.get("normalized_findings")
        if normalized:
            for finding in normalized:
                rows.append(
                    {
                        "target": target,
                        "module": "+".join(finding.get("sources", [])),
                        "category": finding.get("category", ""),
                        "title": finding.get("title", ""),
                        "value": _flatten(finding.get("value", "")),
                        "severity": finding.get("severity", ""),
                        "confidence": finding.get("confidence", ""),
                        "status": finding.get("status", ""),
                        "sources": "+".join(finding.get("sources", [])),
                        "evidence": finding.get("evidence", ""),
                    }
                )
            return rows

        # Fall back to the raw per-module findings map.
        for module, data in self.results.get("findings", {}).items():
            for key, value in _iter_leaves(data):
                rows.append(
                    {
                        "target": target,
                        "module": module,
                        "category": key,
                        "title": key,
                        "value": _flatten(value),
                        "severity": "info",
                        "confidence": "",
                        "status": "",
                        "sources": module,
                        "evidence": "",
                    }
                )
        return rows

    def save(self, path: str) -> str:
        rows = self._rows()
        # utf-8-sig so Excel opens UTF-8 cleanly.
        with open(path, "w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=COLUMNS, extrasaction="ignore")
            writer.writeheader()
            for row in rows:
                writer.writerow(row)
        return path


def _flatten(value: Any) -> str:
    if isinstance(value, (list, tuple, set)):
        return "; ".join(_flatten(v) for v in value)
    if isinstance(value, dict):
        return "; ".join(f"{k}={_flatten(v)}" for k, v in sorted(value.items()))
    return str(value)


def _iter_leaves(data: Any, prefix: str = ""):
    if isinstance(data, dict):
        for key, value in data.items():
            if str(key).startswith("_"):
                continue
            label = f"{prefix}.{key}" if prefix else str(key)
            yield from _iter_leaves(value, label)
    elif isinstance(data, list):
        yield prefix, data
    else:
        yield prefix, data

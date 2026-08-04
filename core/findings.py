"""
WebOSINT Pro - Normalized findings, deduplication and confidence scoring

Every module can emit ``Finding`` objects. The collector:
  * normalizes the identifier so the same fact found by two modules collapses
    into a single entry (stable ``fingerprint``)
  * merges sources, evidence and confidence instead of printing twice
  * assigns a status label so false positives are visible rather than implied
  * produces deterministic, sorted, machine-readable output
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from core.redaction import DEFAULT_REDACTOR, Redactor


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Status(str, Enum):
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    POSSIBLE = "possible"
    UNVERIFIED = "unverified"
    UNTRUSTED = "untrusted"  # produced while TLS verification was disabled


SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

_NORMALIZE_RE = re.compile(r"[^a-z0-9]+")


def normalize_identifier(value: Any) -> str:
    """Stable, lower-case, punctuation-collapsed identifier used for dedup."""
    text = str(value or "").strip().lower().rstrip(".")
    text = re.sub(r"^https?://", "", text)
    text = _NORMALIZE_RE.sub("-", text).strip("-")
    return text


def status_for_confidence(confidence: float) -> Status:
    if confidence >= 0.9:
        return Status.CONFIRMED
    if confidence >= 0.7:
        return Status.LIKELY
    if confidence >= 0.4:
        return Status.POSSIBLE
    return Status.UNVERIFIED


@dataclass(slots=True)
class Finding:
    """A single normalized observation."""

    module: str
    category: str
    title: str
    value: Any = ""
    severity: Severity = Severity.INFO
    confidence: float = 0.5
    status: Status | None = None
    evidence: str = ""
    sources: list[str] = field(default_factory=list)
    target: str = ""
    tags: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.confidence = max(0.0, min(float(self.confidence), 1.0))
        if isinstance(self.severity, str):
            self.severity = Severity(self.severity.lower())
        if self.status is None:
            self.status = status_for_confidence(self.confidence)
        if not self.sources:
            self.sources = [self.module]

    @property
    def key(self) -> str:
        """Normalized dedup key: category + identifier, module independent."""
        return f"{normalize_identifier(self.category)}:{normalize_identifier(self.identifier)}"

    @property
    def identifier(self) -> str:
        base = self.value if self.value not in (None, "", [], {}) else self.title
        if isinstance(base, (list, tuple, set)):
            base = ",".join(sorted(str(b) for b in base))
        if isinstance(base, dict):
            base = ",".join(f"{k}={v}" for k, v in sorted(base.items()))
        return str(base)

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self.key.encode("utf-8")).hexdigest()[:16]

    def to_dict(self, redactor: Redactor | None = None) -> dict[str, Any]:
        red = redactor or DEFAULT_REDACTOR
        return {
            "id": self.fingerprint,
            "category": self.category,
            "title": red.text(self.title),
            "value": red.data(self.value),
            "severity": self.severity.value,
            "confidence": round(self.confidence, 2),
            "status": (self.status or Status.UNVERIFIED).value,
            "evidence": red.text(self.evidence) if self.evidence else "",
            "sources": sorted(set(self.sources)),
            "tags": sorted(set(self.tags)),
            "target": self.target,
        }


class FindingCollector:
    """Thread-safe store that deduplicates findings across modules."""

    def __init__(self, redactor: Redactor | None = None, untrusted: bool = False) -> None:
        self._items: dict[str, Finding] = {}
        self._lock = threading.Lock()
        self._redactor = redactor or DEFAULT_REDACTOR
        self._untrusted = untrusted
        self.duplicates: int = 0

    def __len__(self) -> int:
        return len(self._items)

    def add(self, finding: Finding) -> Finding:
        """Add or merge a finding. Returns the stored (possibly merged) finding."""
        if self._untrusted:
            finding.status = Status.UNTRUSTED
        with self._lock:
            existing = self._items.get(finding.key)
            if existing is None:
                self._items[finding.key] = finding
                return finding

            self.duplicates += 1
            existing.sources = sorted(set(existing.sources) | set(finding.sources))
            existing.tags = sorted(set(existing.tags) | set(finding.tags))
            # Independent corroboration raises confidence, capped at 0.99.
            if finding.confidence > existing.confidence or len(existing.sources) > 1:
                boost = 0.1 if len(existing.sources) > 1 else 0.0
                existing.confidence = min(
                    0.99, max(existing.confidence, finding.confidence) + boost
                )
            if SEVERITY_ORDER[finding.severity] < SEVERITY_ORDER[existing.severity]:
                existing.severity = finding.severity
            if finding.evidence and finding.evidence not in existing.evidence:
                combined = "; ".join(x for x in (existing.evidence, finding.evidence) if x)
                existing.evidence = combined[:400]
            if not self._untrusted:
                existing.status = status_for_confidence(existing.confidence)
            return existing

    def extend(self, findings: list[Finding]) -> None:
        for item in findings:
            self.add(item)

    def all(self) -> list[Finding]:
        """Deterministic ordering: severity, then confidence desc, then key."""
        with self._lock:
            items = list(self._items.values())
        return sorted(
            items,
            key=lambda f: (SEVERITY_ORDER[f.severity], -f.confidence, f.category, f.key),
        )

    def actionable(self, min_severity: Severity = Severity.LOW) -> list[Finding]:
        limit = SEVERITY_ORDER[min_severity]
        return [f for f in self.all() if SEVERITY_ORDER[f.severity] <= limit]

    def counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for finding in self.all():
            counts[finding.severity.value] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": len(self._items),
            "duplicates_merged": self.duplicates,
            "severity_counts": self.counts(),
            "findings": [f.to_dict(self._redactor) for f in self.all()],
        }

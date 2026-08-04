"""
Typed domain model for the WebOSINT Pro engine.

These objects are the contract between plugins, the correlation engine, and the
report engine. They are plain dataclasses so they stay cheap to construct in hot
loops; validation lives in :mod:`engine.schemas` for the API boundary.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Impact of a finding, independent of how sure we are that it is real."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> float:
        return _SEVERITY_WEIGHTS[self]

    @classmethod
    def parse(cls, value: Any, default: Severity | None = None) -> Severity:
        if isinstance(value, cls):
            return value
        try:
            return cls(str(value).strip().lower())
        except ValueError:
            return default or cls.INFO


_SEVERITY_WEIGHTS: dict[Severity, float] = {
    Severity.CRITICAL: 10.0,
    Severity.HIGH: 7.5,
    Severity.MEDIUM: 5.0,
    Severity.LOW: 2.5,
    Severity.INFO: 0.5,
}


class EvidenceKind(str, Enum):
    """Where a piece of evidence came from.

    Independent kinds corroborate each other; two pieces of the same kind are
    treated as weakly correlated by the confidence engine.
    """

    HEADER = "header"
    HTML = "html"
    JS = "js"
    FAVICON = "favicon"
    API = "api"
    DNS = "dns"
    TLS = "tls"
    PORT = "port"
    BANNER = "banner"
    COOKIE = "cookie"
    STATUS = "status"
    REDIRECT = "redirect"
    WHOIS = "whois"
    CERT = "cert"
    FILE = "file"
    BEHAVIOUR = "behaviour"


class ValidationMethod(str, Enum):
    """How a finding was checked before being reported."""

    NONE = "none"
    PASSIVE_OBSERVATION = "passive-observation"
    SIGNATURE_MATCH = "signature-match"
    MULTI_INDICATOR = "multi-indicator"
    ACTIVE_PROBE = "active-probe"
    CROSS_MODULE = "cross-module"
    EXTERNAL_SOURCE = "external-source"


class Exploitability(str, Enum):
    """How readily an issue could be abused in practice."""

    NOT_APPLICABLE = "not-applicable"
    THEORETICAL = "theoretical"
    DIFFICULT = "difficult"
    MODERATE = "moderate"
    EASY = "easy"
    TRIVIAL = "trivial"

    @property
    def multiplier(self) -> float:
        return _EXPLOITABILITY_MULTIPLIERS[self]


_EXPLOITABILITY_MULTIPLIERS: dict[Exploitability, float] = {
    Exploitability.NOT_APPLICABLE: 0.4,
    Exploitability.THEORETICAL: 0.6,
    Exploitability.DIFFICULT: 0.75,
    Exploitability.MODERATE: 0.9,
    Exploitability.EASY: 1.0,
    Exploitability.TRIVIAL: 1.1,
}


class Surface(str, Enum):
    """Attack-surface class, used to decide which plugins are worth running."""

    STATIC_SITE = "static-site"
    DYNAMIC_APP = "dynamic-app"
    SPA = "spa"
    API = "api"
    CMS = "cms"
    CDN_EDGE = "cdn-edge"
    OBJECT_STORAGE = "object-storage"
    MAIL = "mail"
    NETWORK_HOST = "network-host"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class Evidence:
    """A single, citable observation supporting a finding.

    ``value`` is redacted before it reaches a report; ``locator`` records where
    the observation came from so a human can independently reproduce it.
    """

    kind: EvidenceKind
    summary: str
    value: str = ""
    locator: str = ""
    weight: float = 1.0
    observed_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "summary": self.summary,
            "value": self.value,
            "locator": self.locator,
            "weight": round(self.weight, 3),
            "observed_at": self.observed_at,
        }


@dataclass(slots=True)
class Finding:
    """A single reported observation with full provenance and scoring.

    Every field the confidence engine needs is present on the object itself, so
    a finding can be re-scored later without re-running the plugin.
    """

    plugin: str
    title: str
    severity: Severity = Severity.INFO
    description: str = ""
    target: str = ""
    evidence: list[Evidence] = field(default_factory=list)
    validation_method: ValidationMethod = ValidationMethod.NONE
    exploitability: Exploitability = Exploitability.NOT_APPLICABLE
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    cwe: list[str] = field(default_factory=list)
    cve: list[str] = field(default_factory=list)
    owasp: list[str] = field(default_factory=list)
    mitre: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    # Scoring, populated by engine.confidence.score_finding().
    confidence: float = 0.0
    verified: bool = False
    risk_score: float = 0.0
    false_positive_probability: float = 1.0
    suppressed: bool = False
    suppression_reason: str = ""

    @property
    def fingerprint(self) -> str:
        """Stable identity used to deduplicate across plugins and scans."""
        basis = f"{self.plugin}|{self.title}|{self.target}".lower()
        return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]

    @property
    def evidence_kinds(self) -> set[EvidenceKind]:
        return {item.kind for item in self.evidence}

    def add_evidence(self, *items: Evidence) -> Finding:
        self.evidence.extend(items)
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.fingerprint,
            "plugin": self.plugin,
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "target": self.target,
            "confidence": round(self.confidence, 1),
            "verified": self.verified,
            "risk_score": round(self.risk_score, 1),
            "false_positive_probability": round(self.false_positive_probability, 3),
            "validation_method": self.validation_method.value,
            "exploitability": self.exploitability.value,
            "evidence": [item.to_dict() for item in self.evidence],
            "remediation": self.remediation,
            "references": list(self.references),
            "cwe": list(self.cwe),
            "cve": list(self.cve),
            "owasp": list(self.owasp),
            "mitre": list(self.mitre),
            "tags": list(self.tags),
            "metadata": dict(self.metadata),
            "suppressed": self.suppressed,
            "suppression_reason": self.suppression_reason,
        }


@dataclass(slots=True)
class Technology:
    """A detected technology with its own confidence and evidence trail."""

    name: str
    category: str = "unknown"
    version: str = ""
    confidence: float = 0.0
    evidence: list[Evidence] = field(default_factory=list)

    @property
    def slug(self) -> str:
        return self.name.strip().lower().replace(" ", "-")

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "slug": self.slug,
            "category": self.category,
            "version": self.version,
            "confidence": round(self.confidence, 1),
            "evidence": [item.to_dict() for item in self.evidence],
        }


@dataclass(slots=True)
class Asset:
    """A discovered element of the attack surface."""

    identifier: str
    kind: str = "host"
    source: str = ""
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "identifier": self.identifier,
            "kind": self.kind,
            "source": self.source,
            "attributes": dict(self.attributes),
        }


@dataclass(slots=True)
class PluginOutcome:
    """Result of one plugin execution, including timing and failure detail."""

    plugin: str
    status: str = "pending"
    findings: list[Finding] = field(default_factory=list)
    technologies: list[Technology] = field(default_factory=list)
    assets: list[Asset] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)
    duration_ms: int = 0
    error: str = ""
    skipped_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "plugin": self.plugin,
            "status": self.status,
            "duration_ms": self.duration_ms,
            "finding_count": len(self.findings),
            "error": self.error,
            "skipped_reason": self.skipped_reason,
        }

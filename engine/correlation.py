"""
Correlation and analysis engine (the "AI engine").

This is deliberately a *deterministic reasoning* engine rather than a
free-generation one. Every sentence it produces is derived from findings that
are already in the result set, and every claim carries the evidence that
supports it. Nothing is invented, so the output can be pasted into a customer
report without a fact-check pass.

An optional LLM can be attached for prose polish, but it is never allowed to
introduce facts: it receives only the structured summary produced here.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any

from engine.models import Evidence, EvidenceKind, Finding, Severity, ValidationMethod

#: Remediation guidance keyed by finding tag. Sourced from public standards.
REMEDIATION: dict[str, str] = {
    "missing-security-header": (
        "Add the missing response headers at the edge (CDN or reverse proxy) so "
        "every origin inherits them. Start with Content-Security-Policy, "
        "Strict-Transport-Security and Referrer-Policy."
    ),
    "weak-tls": (
        "Disable TLS 1.0/1.1 and CBC cipher suites. Serve TLS 1.2 with AEAD "
        "suites and TLS 1.3, and enable HSTS once the change is verified."
    ),
    "expired-certificate": (
        "Renew the certificate and automate renewal (ACME) with expiry alerting "
        "at 30, 14 and 7 days."
    ),
    "information-disclosure": (
        "Suppress verbose banners and error pages. Return generic errors and "
        "strip framework or version identifiers at the edge."
    ),
    "version-disclosure": (
        "Remove Server and X-Powered-By version strings; they give an attacker "
        "a free CVE shortlist without adding functionality."
    ),
    "exposed-secret": (
        "Revoke and rotate the exposed credential immediately, then remove it "
        "from the artefact and add secret scanning to CI to prevent recurrence."
    ),
    "exposed-service": (
        "Restrict the service to trusted networks with a firewall or security "
        "group, and require authentication if it must remain reachable."
    ),
    "exposed-database": (
        "Remove the database from the public internet immediately, enable "
        "authentication, and audit access logs for prior unauthorised use."
    ),
    "directory-listing": ("Disable automatic directory indexing in the web server configuration."),
    "mail-spoofing": (
        "Publish SPF, DKIM and DMARC on the organizational domain, and add a "
        "null MX plus 'v=spf1 -all' on hostnames that never send mail."
    ),
    "known-vulnerability": (
        "Patch to a fixed release. If patching is blocked, apply a virtual patch "
        "at the WAF and track the exception with an owner and a review date."
    ),
    "subdomain-takeover": (
        "Remove the dangling DNS record or reclaim the referenced resource. "
        "Dangling CNAMEs are trivially exploitable and should be treated as urgent."
    ),
    "dnssec": (
        "Enable DNSSEC at the registrar and DNS provider to prevent response "
        "forgery against your zone."
    ),
    "cookie-security": ("Set Secure, HttpOnly and SameSite on every session cookie."),
}

#: Findings that reinforce each other when seen together.
CORRELATION_RULES: tuple[tuple[frozenset[str], str, Severity], ...] = (
    (
        frozenset({"version-disclosure", "known-vulnerability"}),
        "Disclosed software versions match known vulnerabilities, which removes "
        "the reconnaissance effort an attacker would otherwise need.",
        Severity.HIGH,
    ),
    (
        frozenset({"exposed-service", "weak-tls"}),
        "An internet-reachable service is negotiating weak transport security, "
        "so traffic to it is both discoverable and interceptable.",
        Severity.HIGH,
    ),
    (
        frozenset({"mail-spoofing", "information-disclosure"}),
        "Weak mail authentication combined with disclosed organisational detail "
        "materially raises the success rate of targeted phishing.",
        Severity.MEDIUM,
    ),
    (
        frozenset({"directory-listing", "exposed-secret"}),
        "Browsable directories are exposing files that contain credentials.",
        Severity.CRITICAL,
    ),
)


@dataclass(slots=True)
class Insight:
    """A derived conclusion, always traceable to its source findings."""

    title: str
    detail: str
    severity: Severity
    supporting_findings: list[str] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "detail": self.detail,
            "severity": self.severity.value,
            "supporting_findings": list(self.supporting_findings),
            "evidence": [item.to_dict() for item in self.evidence],
        }


@dataclass(slots=True)
class Analysis:
    """The complete analytical output for one scan."""

    executive_summary: str = ""
    soc_summary: str = ""
    developer_summary: str = ""
    insights: list[Insight] = field(default_factory=list)
    priorities: list[dict[str, Any]] = field(default_factory=list)
    false_positive_candidates: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "executive_summary": self.executive_summary,
            "soc_summary": self.soc_summary,
            "developer_summary": self.developer_summary,
            "insights": [item.to_dict() for item in self.insights],
            "priorities": list(self.priorities),
            "false_positive_candidates": list(self.false_positive_candidates),
        }


def _tag_index(findings: list[Finding]) -> dict[str, list[Finding]]:
    index: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        for tag in finding.tags:
            index[tag.lower()].append(finding)
    return index


def derive_insights(findings: list[Finding]) -> list[Insight]:
    """Apply correlation rules to findings that are already evidenced."""
    index = _tag_index(findings)
    insights: list[Insight] = []

    for tags, detail, severity in CORRELATION_RULES:
        if not all(index.get(tag) for tag in tags):
            continue
        supporting = [finding for tag in tags for finding in index[tag]]
        evidence: list[Evidence] = []
        for finding in supporting:
            evidence.extend(finding.evidence[:2])
        insights.append(
            Insight(
                title="Combined exposure: " + " + ".join(sorted(tags)),
                detail=detail,
                severity=severity,
                supporting_findings=[finding.title for finding in supporting],
                evidence=evidence[:6],
            )
        )

    return insights


def prioritize(findings: list[Finding], limit: int = 10) -> list[dict[str, Any]]:
    """Rank what to fix first: risk, weighted by how cheap the fix is."""
    ranked = sorted(
        findings,
        key=lambda item: (item.risk_score, item.confidence),
        reverse=True,
    )
    priorities: list[dict[str, Any]] = []
    for position, finding in enumerate(ranked[:limit], start=1):
        remediation = finding.remediation
        if not remediation:
            for tag in finding.tags:
                if tag.lower() in REMEDIATION:
                    remediation = REMEDIATION[tag.lower()]
                    break
        priorities.append(
            {
                "rank": position,
                "title": finding.title,
                "severity": finding.severity.value,
                "confidence": round(finding.confidence, 1),
                "risk_score": finding.risk_score,
                "exploitability": finding.exploitability.value,
                "remediation": remediation or "Review the evidence and apply vendor guidance.",
                "evidence_count": len(finding.evidence),
                "evidence_kinds": sorted(kind.value for kind in finding.evidence_kinds),
            }
        )
    return priorities


def flag_false_positives(findings: list[Finding]) -> list[dict[str, Any]]:
    """Surface findings whose support is thin enough to warrant a human look."""
    candidates: list[dict[str, Any]] = []
    for finding in findings:
        reasons: list[str] = []
        if len(finding.evidence_kinds) < 2:
            reasons.append("only one independent evidence kind")
        if finding.false_positive_probability > 0.25:
            reasons.append(
                f"estimated false-positive probability {finding.false_positive_probability:.0%}"
            )
        if finding.validation_method in (
            ValidationMethod.NONE,
            ValidationMethod.PASSIVE_OBSERVATION,
        ) and finding.severity in (Severity.CRITICAL, Severity.HIGH):
            reasons.append("high severity asserted from passive observation alone")
        if reasons:
            candidates.append(
                {
                    "title": finding.title,
                    "plugin": finding.plugin,
                    "severity": finding.severity.value,
                    "confidence": round(finding.confidence, 1),
                    "reasons": reasons,
                }
            )
    return candidates


def _describe_posture(counts: dict[str, int], risk_score: float) -> str:
    if counts["critical"]:
        return "critical"
    if counts["high"]:
        return "poor"
    if risk_score >= 20:
        return "mixed"
    if counts["medium"]:
        return "reasonable"
    return "strong"


def analyse(result: Any) -> Analysis:
    """Produce the full analysis for a :class:`~engine.pipeline.ScanResult`.

    Every statement below is a direct restatement of scan data. If the scan
    found nothing, the summary says so rather than padding.
    """
    findings = list(getattr(result, "reported", []) or [])
    counts = result.severity_counts()
    target = result.target
    risk_score = float(getattr(result, "risk_score", 0.0))
    posture = _describe_posture(counts, risk_score)

    analysis = Analysis()
    analysis.insights = derive_insights(findings)
    analysis.priorities = prioritize(findings)
    analysis.false_positive_candidates = flag_false_positives(findings)

    technologies = [tech.name for tech in getattr(result, "technologies", [])]
    tech_text = ", ".join(technologies[:6]) if technologies else "no conclusively identified stack"

    total = len(findings)
    suppressed = len(getattr(result, "suppressed", []) or [])

    analysis.executive_summary = (
        f"The external attack surface of {target} was assessed and rated {posture} "
        f"(risk score {risk_score:.1f}/100). The target presents as a "
        f"{result.surface.value.replace('_', ' ')} built on {tech_text}. "
        f"{total} finding(s) met the reporting confidence threshold: "
        f"{counts['critical']} critical, {counts['high']} high, {counts['medium']} medium, "
        f"{counts['low']} low and {counts['info']} informational. "
        + (
            f"A further {suppressed} candidate finding(s) were withheld because the "
            f"supporting evidence was too weak to assert confidently."
            if suppressed
            else "No findings were withheld for weak evidence."
        )
    )

    top_kinds = Counter(
        kind.value for finding in findings for kind in finding.evidence_kinds
    ).most_common(4)
    kinds_text = ", ".join(f"{kind} ({count})" for kind, count in top_kinds) or "none"

    verified = sum(1 for finding in findings if finding.verified)
    analysis.soc_summary = (
        f"Detection summary for {target}. {verified} of {total} reported findings are "
        f"independently verified by two or more evidence kinds. Primary evidence "
        f"channels: {kinds_text}. "
        + (
            "Correlated exposure detected: "
            + "; ".join(insight.title for insight in analysis.insights)
            + "."
            if analysis.insights
            else "No multi-factor exposure chains were identified."
        )
        + (
            f" {len(analysis.false_positive_candidates)} finding(s) are flagged for analyst "
            f"review before escalation."
            if analysis.false_positive_candidates
            else " No findings require analyst adjudication."
        )
    )

    if analysis.priorities:
        top = analysis.priorities[:3]
        actions = " ".join(
            f"{item['rank']}. {item['title']} ({item['severity']}): {item['remediation']}"
            for item in top
        )
        analysis.developer_summary = f"Highest-value fixes for {target}, ordered by risk: {actions}"
    else:
        analysis.developer_summary = (
            f"No confidently evidenced defects require developer action on {target}."
        )

    return analysis


def evidence_bundle(finding: Finding) -> list[dict[str, Any]]:
    """Full provenance for one finding, for the appendix of a report."""
    return [item.to_dict() for item in finding.evidence]


def evidence_kind_coverage(findings: list[Finding]) -> dict[str, int]:
    """How often each evidence kind contributed, for QA of the detection set."""
    counter: Counter[str] = Counter()
    for finding in findings:
        for kind in finding.evidence_kinds:
            counter[kind.value] += 1
    return {kind.value: counter.get(kind.value, 0) for kind in EvidenceKind}

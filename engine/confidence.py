"""
Evidence-weighted confidence and risk scoring.

Design rules, derived from how commercial ASM tools avoid noise:

1. A single indicator is never enough. One piece of evidence caps confidence
   well below the reporting threshold.
2. *Independent* evidence kinds corroborate strongly; repeats of the same kind
   add sharply diminishing value (a second header proves little more than the
   first).
3. Active verification beats passive inference.
4. Confidence and severity are orthogonal. A critical issue we are unsure about
   must not masquerade as a confirmed one; risk score combines the two.
"""

from __future__ import annotations

from dataclasses import dataclass

from engine.models import (
    Evidence,
    Exploitability,
    Finding,
    Severity,
    ValidationMethod,
)

#: Confidence at or above which a finding is reported by default.
REPORTING_THRESHOLD = 80.0

#: Confidence at or above which a finding is marked ``verified``.
VERIFIED_THRESHOLD = 90.0

#: How much each validation method is trusted.
VALIDATION_WEIGHTS: dict[ValidationMethod, float] = {
    ValidationMethod.NONE: 0.45,
    ValidationMethod.PASSIVE_OBSERVATION: 0.70,
    ValidationMethod.SIGNATURE_MATCH: 0.80,
    ValidationMethod.MULTI_INDICATOR: 0.92,
    ValidationMethod.CROSS_MODULE: 0.95,
    ValidationMethod.EXTERNAL_SOURCE: 0.85,
    ValidationMethod.ACTIVE_PROBE: 1.0,
}

#: Intrinsic reliability of each evidence kind. Headers and DNS are strong and
#: hard to fake accidentally; HTML body text is comparatively weak.
KIND_RELIABILITY: dict[str, float] = {
    "dns": 1.0,
    "tls": 1.0,
    "cert": 1.0,
    "header": 0.95,
    "api": 0.95,
    "port": 0.9,
    "banner": 0.9,
    "favicon": 0.85,
    "cookie": 0.85,
    "js": 0.8,
    "redirect": 0.8,
    "file": 0.8,
    "whois": 0.8,
    "status": 0.6,
    "html": 0.6,
    "behaviour": 0.7,
}

#: Diminishing returns for repeated evidence of the *same* kind.
_REPEAT_DECAY = 0.35

#: Corroboration bonus per additional independent evidence kind.
_DIVERSITY_BONUS = 0.13


@dataclass(frozen=True, slots=True)
class ConfidenceBreakdown:
    """Explains a score so an analyst can audit why something was reported."""

    confidence: float
    evidence_strength: float
    diversity_factor: float
    validation_weight: float
    distinct_kinds: int
    evidence_count: int

    def to_dict(self) -> dict[str, float | int]:
        return {
            "confidence": round(self.confidence, 1),
            "evidence_strength": round(self.evidence_strength, 3),
            "diversity_factor": round(self.diversity_factor, 3),
            "validation_weight": round(self.validation_weight, 3),
            "distinct_kinds": self.distinct_kinds,
            "evidence_count": self.evidence_count,
        }


def evidence_strength(evidence: list[Evidence]) -> float:
    """Combined strength of an evidence set, in the range 0..1.

    Uses a noisy-OR style combination: each independent item removes part of the
    remaining doubt, so strength approaches but never reaches certainty.
    """
    if not evidence:
        return 0.0

    seen_per_kind: dict[str, int] = {}
    remaining_doubt = 1.0

    # Strongest evidence first so decay penalises the weakest repeats.
    ordered = sorted(
        evidence,
        key=lambda item: KIND_RELIABILITY.get(item.kind.value, 0.6) * max(item.weight, 0.0),
        reverse=True,
    )

    for item in ordered:
        kind = item.kind.value
        occurrence = seen_per_kind.get(kind, 0)
        seen_per_kind[kind] = occurrence + 1

        reliability = KIND_RELIABILITY.get(kind, 0.6)
        weight = min(max(item.weight, 0.0), 2.0)
        decay = _REPEAT_DECAY**occurrence
        contribution = reliability * weight * decay
        remaining_doubt *= 1.0 - min(contribution, 0.97)

    return 1.0 - remaining_doubt


def diversity_factor(distinct_kinds: int) -> float:
    """Reward corroboration from independent observation channels."""
    if distinct_kinds <= 0:
        return 0.0
    if distinct_kinds == 1:
        # A lone indicator is explicitly capped below the reporting threshold.
        return 0.72
    return min(1.0, 0.85 + _DIVERSITY_BONUS * (distinct_kinds - 1))


def score_finding(finding: Finding, *, threshold: float = REPORTING_THRESHOLD) -> Finding:
    """Populate confidence, verification, risk and FP probability in place."""
    strength = evidence_strength(finding.evidence)
    kinds = len(finding.evidence_kinds)
    diversity = diversity_factor(kinds)
    validation = VALIDATION_WEIGHTS.get(finding.validation_method, 0.5)

    confidence = 100.0 * strength * diversity * validation
    confidence = max(0.0, min(100.0, confidence))

    finding.confidence = confidence
    finding.verified = confidence >= VERIFIED_THRESHOLD and kinds >= 2
    finding.false_positive_probability = round(max(0.0, 1.0 - confidence / 100.0), 3)

    # Risk blends impact, certainty and how easily the issue can be abused.
    finding.risk_score = round(
        finding.severity.weight * (confidence / 100.0) * finding.exploitability.multiplier,
        2,
    )

    if confidence < threshold and finding.severity is not Severity.INFO:
        finding.suppressed = True
        finding.suppression_reason = (
            f"Confidence {confidence:.0f}% is below the {threshold:.0f}% reporting "
            f"threshold ({kinds} independent indicator(s))."
        )
    else:
        finding.suppressed = False
        finding.suppression_reason = ""

    return finding


def explain(finding: Finding) -> ConfidenceBreakdown:
    """Recompute the score components for audit and reporting."""
    strength = evidence_strength(finding.evidence)
    kinds = len(finding.evidence_kinds)
    diversity = diversity_factor(kinds)
    validation = VALIDATION_WEIGHTS.get(finding.validation_method, 0.5)
    return ConfidenceBreakdown(
        confidence=max(0.0, min(100.0, 100.0 * strength * diversity * validation)),
        evidence_strength=strength,
        diversity_factor=diversity,
        validation_weight=validation,
        distinct_kinds=kinds,
        evidence_count=len(finding.evidence),
    )


def infer_exploitability(finding: Finding) -> Exploitability:
    """Best-effort exploitability when a plugin does not supply one."""
    tags = {tag.lower() for tag in finding.tags}
    if "unauthenticated" in tags and "exposed" in tags:
        return Exploitability.TRIVIAL
    if "exposed" in tags or finding.cve:
        return Exploitability.EASY
    if finding.severity in (Severity.CRITICAL, Severity.HIGH):
        return Exploitability.MODERATE
    if finding.severity is Severity.INFO:
        return Exploitability.NOT_APPLICABLE
    return Exploitability.DIFFICULT


def aggregate_risk(findings: list[Finding]) -> float:
    """Overall 0-100 posture score for a target.

    Dominated by the worst issue rather than the count, so a hundred info notes
    never outweigh one confirmed critical.
    """
    live = [item for item in findings if not item.suppressed]
    if not live:
        return 0.0
    scores = sorted((item.risk_score for item in live), reverse=True)
    top = scores[0]
    tail = sum(score * (0.5 ** (index + 1)) for index, score in enumerate(scores[1:]))
    return round(min(100.0, (top + tail) * 10.0), 1)

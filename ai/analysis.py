"""
AI-assisted finding analysis with deterministic offline fallback.

This module intentionally avoids requiring a cloud model. A future adapter can
call an LLM, while the rule-based analyzer gives stable risk scoring today.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SEVERITY_WEIGHT = {
    "critical": 100,
    "high": 75,
    "medium": 50,
    "low": 25,
    "info": 5,
}


@dataclass(slots=True)
class AnalysisResult:
    score: int
    priority: str
    summary: str
    attack_paths: list[str] = field(default_factory=list)
    remediation: list[str] = field(default_factory=list)


class FindingAnalyzer:
    """Correlates module output into a prioritized scan narrative."""

    def analyze(self, results: dict[str, Any]) -> AnalysisResult:
        findings = results.get("findings", {})
        risk_counts = results.get("summary", {}).get("risk_counts", {})
        score = self._score(risk_counts)
        priority = self._priority(score)
        attack_paths = self._attack_paths(findings)
        remediation = self._remediation(findings)
        summary = self._summary(score, priority, risk_counts, attack_paths)
        return AnalysisResult(
            score=score,
            priority=priority,
            summary=summary,
            attack_paths=attack_paths,
            remediation=remediation,
        )

    def _score(self, risk_counts: dict[str, int]) -> int:
        raw = sum(
            SEVERITY_WEIGHT.get(level, 0) * int(count) for level, count in risk_counts.items()
        )
        return min(100, raw)

    def _priority(self, score: int) -> str:
        if score >= 85:
            return "critical"
        if score >= 65:
            return "high"
        if score >= 35:
            return "medium"
        if score >= 10:
            return "low"
        return "info"

    def _attack_paths(self, findings: dict[str, Any]) -> list[str]:
        paths: list[str] = []
        js = findings.get("javascript", {})
        ports = findings.get("ports", {})
        http = findings.get("http", {})
        if isinstance(js, dict) and (js.get("secrets") or js.get("inline_secrets")):
            paths.append(
                "Validate exposed JavaScript secrets, then test associated APIs for privilege impact."
            )
        if isinstance(ports, dict) and ports.get("dangerous_ports"):
            paths.append(
                "Review exposed administrative services and test access controls from the internet."
            )
        if isinstance(http, dict) and http.get("missing_security_headers"):
            paths.append(
                "Correlate missing browser security controls with XSS, clickjacking, and data exposure findings."
            )
        return paths

    def _remediation(self, findings: dict[str, Any]) -> list[str]:
        recs: list[str] = []
        for module, data in findings.items():
            if not isinstance(data, dict):
                continue
            for key, value in data.items():
                if str(key).startswith("_risk") and str(value) in {"critical", "high", "medium"}:
                    label = str(key)[6:].replace("_", " ")
                    recs.append(
                        f"Review {label} reported by {module} and validate remediation with a retest."
                    )
        return recs[:20]

    def _summary(
        self,
        score: int,
        priority: str,
        risk_counts: dict[str, int],
        attack_paths: list[str],
    ) -> str:
        high_signal = risk_counts.get("critical", 0) + risk_counts.get("high", 0)
        if high_signal:
            return f"Scan priority is {priority} with risk score {score}; {high_signal} high-signal issue(s) need review."
        if attack_paths:
            return f"Scan priority is {priority} with risk score {score}; correlation found plausible follow-up paths."
        return f"Scan priority is {priority} with risk score {score}; no high-signal issue correlation found."

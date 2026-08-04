"""
Control-framework mapping.

Findings carry a small set of stable tags; this module translates those tags
into the frameworks enterprise readers actually report against. Mappings are
intentionally conservative - an unmapped finding is better than a wrong claim
of PCI or NIST coverage.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class ControlMapping:
    """How one finding class maps across the frameworks we report."""

    owasp: tuple[str, ...] = ()
    cwe: tuple[str, ...] = ()
    mitre: tuple[str, ...] = ()
    pci_dss: tuple[str, ...] = ()
    nist: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, list[str]]:
        return {
            "owasp": list(self.owasp),
            "cwe": list(self.cwe),
            "mitre": list(self.mitre),
            "pci_dss": list(self.pci_dss),
            "nist": list(self.nist),
        }

    def is_empty(self) -> bool:
        return not (self.owasp or self.cwe or self.mitre or self.pci_dss or self.nist)


#: Keyed by finding tag. Tags are lowercase and stable across releases.
MAPPINGS: dict[str, ControlMapping] = {
    "missing-security-header": ControlMapping(
        owasp=("A05:2021 Security Misconfiguration",),
        cwe=("CWE-693",),
        mitre=("T1190",),
        pci_dss=("6.4.1",),
        nist=("PR.IP-1",),
    ),
    "weak-tls": ControlMapping(
        owasp=("A02:2021 Cryptographic Failures",),
        cwe=("CWE-326", "CWE-327"),
        mitre=("T1040",),
        pci_dss=("4.2.1",),
        nist=("PR.DS-2",),
    ),
    "expired-certificate": ControlMapping(
        owasp=("A02:2021 Cryptographic Failures",),
        cwe=("CWE-298",),
        pci_dss=("4.2.1",),
        nist=("PR.DS-2",),
    ),
    "information-disclosure": ControlMapping(
        owasp=("A01:2021 Broken Access Control",),
        cwe=("CWE-200",),
        mitre=("T1592",),
        pci_dss=("6.5.5",),
        nist=("PR.DS-5",),
    ),
    "version-disclosure": ControlMapping(
        owasp=("A05:2021 Security Misconfiguration",),
        cwe=("CWE-200",),
        mitre=("T1592.002",),
        nist=("ID.AM-2",),
    ),
    "exposed-secret": ControlMapping(
        owasp=("A07:2021 Identification and Authentication Failures",),
        cwe=("CWE-798", "CWE-540"),
        mitre=("T1552.001",),
        pci_dss=("8.3.1",),
        nist=("PR.AC-1",),
    ),
    "exposed-service": ControlMapping(
        owasp=("A05:2021 Security Misconfiguration",),
        cwe=("CWE-668",),
        mitre=("T1046",),
        pci_dss=("1.2.1",),
        nist=("PR.AC-5",),
    ),
    "exposed-database": ControlMapping(
        owasp=("A01:2021 Broken Access Control",),
        cwe=("CWE-306",),
        mitre=("T1078",),
        pci_dss=("1.3.1",),
        nist=("PR.AC-4",),
    ),
    "directory-listing": ControlMapping(
        owasp=("A05:2021 Security Misconfiguration",),
        cwe=("CWE-548",),
        mitre=("T1083",),
        nist=("PR.DS-5",),
    ),
    "mail-spoofing": ControlMapping(
        owasp=("A07:2021 Identification and Authentication Failures",),
        cwe=("CWE-290",),
        mitre=("T1566",),
        nist=("PR.DS-6",),
    ),
    "known-vulnerability": ControlMapping(
        owasp=("A06:2021 Vulnerable and Outdated Components",),
        cwe=("CWE-1035",),
        mitre=("T1190",),
        pci_dss=("6.3.3",),
        nist=("ID.RA-1",),
    ),
    "subdomain-takeover": ControlMapping(
        owasp=("A05:2021 Security Misconfiguration",),
        cwe=("CWE-350",),
        mitre=("T1584.001",),
        nist=("ID.AM-1",),
    ),
    "dnssec": ControlMapping(
        cwe=("CWE-350",),
        mitre=("T1584.002",),
        nist=("PR.DS-6",),
    ),
    "cookie-security": ControlMapping(
        owasp=("A05:2021 Security Misconfiguration",),
        cwe=("CWE-1004", "CWE-614"),
        pci_dss=("6.4.1",),
        nist=("PR.DS-2",),
    ),
    "attack-surface": ControlMapping(
        mitre=("T1595",),
        nist=("ID.AM-1", "ID.AM-2"),
    ),
}

#: Human-readable descriptions for the frameworks we cite.
FRAMEWORKS: dict[str, str] = {
    "owasp": "OWASP Top 10 (2021)",
    "cwe": "MITRE Common Weakness Enumeration",
    "mitre": "MITRE ATT&CK Enterprise",
    "pci_dss": "PCI DSS v4.0",
    "nist": "NIST Cybersecurity Framework 2.0",
}


@dataclass(slots=True)
class ComplianceSummary:
    """Rolled-up framework coverage across a whole scan."""

    by_framework: dict[str, dict[str, int]] = field(default_factory=dict)
    unmapped: int = 0

    def to_dict(self) -> dict[str, object]:
        return {
            "frameworks": {
                key: {
                    "name": FRAMEWORKS.get(key, key),
                    "controls": dict(sorted(values.items(), key=lambda kv: -kv[1])),
                }
                for key, values in sorted(self.by_framework.items())
            },
            "unmapped_findings": self.unmapped,
        }


def map_tags(tags: list[str] | set[str] | tuple[str, ...]) -> ControlMapping:
    """Merge the mappings for every tag on a finding."""
    owasp: list[str] = []
    cwe: list[str] = []
    mitre: list[str] = []
    pci: list[str] = []
    nist: list[str] = []

    for tag in tags:
        mapping = MAPPINGS.get(str(tag).strip().lower())
        if mapping is None:
            continue
        owasp.extend(mapping.owasp)
        cwe.extend(mapping.cwe)
        mitre.extend(mapping.mitre)
        pci.extend(mapping.pci_dss)
        nist.extend(mapping.nist)

    dedupe = lambda values: tuple(dict.fromkeys(values))  # noqa: E731
    return ControlMapping(
        owasp=dedupe(owasp),
        cwe=dedupe(cwe),
        mitre=dedupe(mitre),
        pci_dss=dedupe(pci),
        nist=dedupe(nist),
    )


def summarize(findings: list[object]) -> ComplianceSummary:
    """Count how many findings touch each control, across all frameworks."""
    summary = ComplianceSummary()
    for finding in findings:
        tags = list(getattr(finding, "tags", ()) or ())
        mapping = map_tags(tags)
        if mapping.is_empty():
            summary.unmapped += 1
            continue
        for framework, controls in mapping.to_dict().items():
            if not controls:
                continue
            bucket = summary.by_framework.setdefault(framework, {})
            for control in controls:
                bucket[control] = bucket.get(control, 0) + 1
    return summary

"""
Bridge from the legacy ``core.base_module.BaseModule`` API to engine plugins.

This is what makes the rewrite non-destructive. All twenty existing modules keep
working exactly as they do today, but they now run inside the new lifecycle and
their output is normalized into evidence-bearing, scored findings.

The adapter translates two legacy output styles:

* ``_risk_<name>: "<severity>"`` markers written by ``set_risk()``
* rows already pushed into the normalized ``FindingCollector``

Evidence is synthesized from the sibling keys in the module's findings dict, so
even legacy detections gain the provenance the confidence engine needs.
"""

from __future__ import annotations

import logging
from typing import Any

from engine.compliance import map_tags
from engine.models import (
    Evidence,
    EvidenceKind,
    Finding,
    Severity,
    ValidationMethod,
)
from engine.plugins import Plugin, ScanContext

LOG = logging.getLogger(__name__)

RISK_PREFIX = "_risk_"

#: Which evidence kind a legacy module's observations most likely represent.
MODULE_EVIDENCE_KIND: dict[str, EvidenceKind] = {
    "dns": EvidenceKind.DNS,
    "mail": EvidenceKind.DNS,
    "subdomains": EvidenceKind.DNS,
    "ssl": EvidenceKind.TLS,
    "http": EvidenceKind.HEADER,
    "waf": EvidenceKind.HEADER,
    "webapp": EvidenceKind.HTML,
    "javascript": EvidenceKind.JS,
    "api": EvidenceKind.API,
    "dirs": EvidenceKind.FILE,
    "ports": EvidenceKind.PORT,
    "database": EvidenceKind.PORT,
    "ip": EvidenceKind.DNS,
    "whois": EvidenceKind.WHOIS,
    "cve": EvidenceKind.BANNER,
    "siem": EvidenceKind.BEHAVIOUR,
    "ids": EvidenceKind.BEHAVIOUR,
    "honeypot": EvidenceKind.BEHAVIOUR,
    "websocket": EvidenceKind.BEHAVIOUR,
    "osint": EvidenceKind.HTML,
}

#: Legacy risk names mapped onto the stable tags the compliance layer knows.
RISK_TAGS: dict[str, tuple[str, ...]] = {
    "missing_headers": ("missing-security-header",),
    "header_disclosure": ("version-disclosure", "information-disclosure"),
    "no_spf": ("mail-spoofing",),
    "no_dmarc": ("mail-spoofing",),
    "no_dkim": ("mail-spoofing",),
    "subdomain_no_spf": ("mail-spoofing",),
    "dmarc_policy_none": ("mail-spoofing",),
    "spf_permissive": ("mail-spoofing",),
    "email_spoofing": ("mail-spoofing",),
    "sensitive_paths": ("information-disclosure",),
    "backup_files": ("information-disclosure", "exposed-secret"),
    "directory_listing": ("directory-listing",),
    "dangerous_ports": ("exposed-service",),
    "exposed_database": ("exposed-database",),
    "weak_ciphers": ("weak-tls",),
    "expired_cert": ("expired-certificate",),
    "self_signed": ("expired-certificate",),
    "no_dnssec": ("dnssec",),
    "secrets": ("exposed-secret",),
    "known_cve": ("known-vulnerability",),
    "takeover": ("subdomain-takeover",),
    "insecure_cookies": ("cookie-security",),
}

#: Legacy risk names rendered as human titles.
TITLE_OVERRIDES: dict[str, str] = {
    "missing_headers": "Missing security headers",
    "header_disclosure": "Information disclosure via response headers",
    "no_spf": "No SPF record published",
    "no_dmarc": "No DMARC record published",
    "no_dkim": "No DKIM selector found",
    "subdomain_no_spf": "Subdomain has no dedicated SPF record",
    "dmarc_policy_none": "DMARC policy is set to none",
    "spf_permissive": "SPF policy is permissive",
    "email_spoofing": "Email spoofing is possible",
    "sensitive_paths": "Sensitive paths are reachable",
    "backup_files": "Backup files are exposed",
    "dangerous_ports": "High-risk ports are exposed",
    "weak_ciphers": "Weak TLS ciphers are supported",
    "expired_cert": "TLS certificate has expired",
    "no_dnssec": "DNSSEC is not enabled",
    "directory_listing": "Directory listing is enabled",
}


def humanize(key: str) -> str:
    if key in TITLE_OVERRIDES:
        return TITLE_OVERRIDES[key]
    return key.replace("_", " ").strip().capitalize()


def _compact(value: Any, limit: int = 220) -> str:
    """Render an arbitrary legacy value as a short evidence string."""
    if value in (None, "", [], {}):
        return ""
    if isinstance(value, list):
        text = "; ".join(_compact(item, 60) for item in value if item not in (None, "", [], {}))
    elif isinstance(value, dict):
        text = "; ".join(
            f"{key}={_compact(item, 60)}"
            for key, item in value.items()
            if item not in (None, "", [], {}) and not str(key).startswith("_risk_")
        )
    else:
        text = str(value)
    text = " ".join(text.split())
    return text[: limit - 3] + "..." if len(text) > limit else text


def _related_keys(risk_name: str, data: dict[str, Any]) -> list[tuple[str, Any]]:
    """Find the data keys that most plausibly justify a given risk marker."""
    words = {word for word in risk_name.split("_") if len(word) > 3}
    hits: list[tuple[str, Any]] = []
    for key, value in data.items():
        if str(key).startswith(RISK_PREFIX) or value in (None, "", [], {}):
            continue
        lowered = str(key).lower()
        if any(word in lowered for word in words):
            hits.append((str(key), value))
    return hits[:4]


def findings_from_legacy_dict(module: str, data: dict[str, Any]) -> list[Finding]:
    """Convert one legacy module's findings dict into engine findings."""
    results: list[Finding] = []
    if not isinstance(data, dict):
        return results

    kind = MODULE_EVIDENCE_KIND.get(module, EvidenceKind.BEHAVIOUR)
    target = str(data.get("target") or data.get("domain") or data.get("scanned_domain") or "")

    for key, level in data.items():
        name = str(key)
        if not name.startswith(RISK_PREFIX):
            continue
        risk_name = name[len(RISK_PREFIX) :]
        severity = Severity.parse(level)

        finding = Finding(
            plugin=module,
            title=humanize(risk_name),
            severity=severity,
            target=target,
            description=f"Reported by the {module} module as {severity.value} risk.",
            validation_method=ValidationMethod.PASSIVE_OBSERVATION,
            tags=list(RISK_TAGS.get(risk_name, ())),
        )

        # The marker itself is one indicator.
        finding.add_evidence(
            Evidence(
                kind=kind,
                summary=f"{module} raised {risk_name}",
                value=str(level),
                locator=name,
                weight=0.9,
            )
        )

        # Sibling data keys supply the corroborating detail.
        for related_key, related_value in _related_keys(risk_name, data):
            rendered = _compact(related_value)
            if not rendered:
                continue
            finding.add_evidence(
                Evidence(
                    kind=kind,
                    summary=f"Supporting data from {module}.{related_key}",
                    value=rendered,
                    locator=related_key,
                    weight=0.7,
                )
            )

        if len(finding.evidence) > 1:
            finding.validation_method = ValidationMethod.MULTI_INDICATOR

        mapping = map_tags(finding.tags)
        finding.cwe = list(mapping.cwe)
        finding.owasp = list(mapping.owasp)
        finding.mitre = list(mapping.mitre)

        results.append(finding)

    return results


def findings_from_collector(module: str, collector: Any) -> list[Finding]:
    """Convert normalized legacy collector rows into engine findings."""
    results: list[Finding] = []
    rows = []
    try:
        rows = collector.all()
    except Exception:
        return results

    kind = MODULE_EVIDENCE_KIND.get(module, EvidenceKind.BEHAVIOUR)
    for row in rows:
        finding = Finding(
            plugin=module,
            title=str(getattr(row, "title", "") or "Observation"),
            severity=Severity.parse(getattr(getattr(row, "severity", None), "value", "info")),
            target=str(getattr(row, "value", "") or ""),
            description=str(getattr(row, "description", "") or ""),
            validation_method=ValidationMethod.SIGNATURE_MATCH,
            tags=list(getattr(row, "tags", ()) or ()),
        )
        evidence_text = str(getattr(row, "evidence", "") or "")
        if evidence_text:
            finding.add_evidence(
                Evidence(
                    kind=kind,
                    summary=f"{module} evidence",
                    value=evidence_text[:220],
                    locator=str(getattr(row, "category", "") or module),
                    weight=1.0,
                )
            )
        confidence = float(getattr(row, "confidence", 0.5) or 0.5)
        finding.add_evidence(
            Evidence(
                kind=kind,
                summary=f"{module} reported confidence {confidence:.0%}",
                value=str(getattr(row, "value", "") or "")[:220],
                locator="collector",
                weight=max(0.4, min(confidence * 1.2, 1.2)),
            )
        )
        results.append(finding)
    return results


class LegacyModulePlugin(Plugin):
    """Wraps one ``BaseModule`` subclass as a first-class engine plugin.

    Instances are produced by :func:`adapt_legacy_module`, which creates a
    dedicated subclass per legacy module so that ``name``, ``version`` and
    ``requires`` are correct class attributes and registry versioning works.
    """

    legacy_class: type[Any] | None = None

    def __init__(self) -> None:
        super().__init__()
        self.instance: Any = None

    def initialize(self, context: ScanContext) -> None:
        super().initialize(context)
        if self.legacy_class is None:
            raise RuntimeError("LegacyModulePlugin requires a legacy_class.")

        factory = context.shared.get("legacy_factory")
        if factory is None:
            raise RuntimeError(
                "No legacy_factory in the scan context; the engine cannot build "
                "legacy modules without the scanner's config and safety objects."
            )
        self.instance = factory(self.legacy_class, self.name)

    def scan(self, context: ScanContext) -> list[Finding]:
        if self.instance is None:
            return []

        raw = self.instance.run() or {}
        if not isinstance(raw, dict):
            raw = {"result": raw}

        # Publish the raw output so other plugins can react without coupling.
        context.bus.publish(
            "legacy.module.output", {"module": self.name, "data": raw}, source=self.name
        )
        context.shared.setdefault("legacy_output", {})[self.name] = raw

        findings = findings_from_legacy_dict(self.name, raw)
        collector = getattr(self.instance, "collector", None)
        if collector is not None:
            findings.extend(findings_from_collector(self.name, collector))
        return findings

    def correlate(self, findings: list[Finding], context: ScanContext) -> list[Finding]:
        """Raise validation strength when another plugin saw the same thing."""
        others = context.shared.get("legacy_output", {})
        for finding in findings:
            corroborating = [
                module
                for module, data in others.items()
                if module != self.name
                and isinstance(data, dict)
                and any(
                    str(key).startswith(RISK_PREFIX)
                    and humanize(str(key)[len(RISK_PREFIX) :]) == finding.title
                    for key in data
                )
            ]
            if corroborating:
                finding.validation_method = ValidationMethod.CROSS_MODULE
                finding.add_evidence(
                    Evidence(
                        kind=EvidenceKind.BEHAVIOUR,
                        summary="Independently reported by " + ", ".join(sorted(corroborating)),
                        value=", ".join(sorted(corroborating)),
                        locator="cross-module",
                        weight=1.0,
                    )
                )
        return findings

    def shutdown(self) -> None:
        if self.instance is not None:
            try:
                self.instance.teardown()
            except Exception:
                LOG.debug("Legacy module %s teardown failed", self.name, exc_info=True)
        self.instance = None
        super().shutdown()


def adapt_legacy_module(legacy_class: type[Any], *, order: int = 100) -> type[LegacyModulePlugin]:
    """Build a plugin class that runs ``legacy_class``."""
    name = str(getattr(legacy_class, "NAME", "") or legacy_class.__name__).strip().lower()

    namespace = {
        "legacy_class": legacy_class,
        "name": name,
        "version": str(getattr(legacy_class, "VERSION", "2.0.0")),
        "description": str(getattr(legacy_class, "DESCRIPTION", "")),
        "category": "legacy",
        "active": bool(getattr(legacy_class, "ACTIVE", False)),
        "requires": tuple(getattr(legacy_class, "REQUIRES", ()) or ()),
        "order": order,
        "__doc__": (
            f"Engine plugin wrapper for the legacy {name} module.\n\n"
            f"{getattr(legacy_class, 'DESCRIPTION', '')}"
        ),
    }
    return type(f"{name.title().replace('_', '')}LegacyPlugin", (LegacyModulePlugin,), namespace)


def register_legacy_modules(registry: Any, modules: dict[str, type[Any]]) -> list[str]:
    """Adapt and register a mapping of ``name -> BaseModule subclass``."""
    registered: list[str] = []
    for index, (name, legacy_class) in enumerate(sorted(modules.items())):
        try:
            plugin_class = adapt_legacy_module(legacy_class, order=100 + index)
            registry.register(plugin_class, source=f"legacy:{name}")
            registered.append(name)
        except Exception as exc:
            LOG.warning("Could not adapt legacy module %s: %s", name, exc)
    return registered

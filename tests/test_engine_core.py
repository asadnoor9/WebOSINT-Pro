"""Unit tests for the engine: models, events, cache, confidence, selection."""

from __future__ import annotations

import threading
import time

import pytest

from engine import cache as cache_module
from engine import confidence as confidence_module
from engine import events as events_module
from engine import fingerprint, selection
from engine.models import (
    Evidence,
    EvidenceKind,
    Exploitability,
    Finding,
    Severity,
    Surface,
    Technology,
    ValidationMethod,
)

# --- models -----------------------------------------------------------------


def test_severity_weights_are_ordered():
    assert Severity.CRITICAL.weight > Severity.HIGH.weight > Severity.MEDIUM.weight
    assert Severity.MEDIUM.weight > Severity.LOW.weight > Severity.INFO.weight


def test_severity_parse_accepts_aliases_and_junk():
    assert Severity.parse("HIGH") is Severity.HIGH
    assert Severity.parse("") is Severity.INFO
    assert Severity.parse("not-a-severity") is Severity.INFO


def test_finding_fingerprint_is_stable_and_distinct():
    first = Finding(plugin="http", title="Missing HSTS", target="example.com")
    same = Finding(plugin="http", title="Missing HSTS", target="example.com")
    other = Finding(plugin="http", title="Missing HSTS", target="other.com")

    assert first.fingerprint == same.fingerprint
    assert first.fingerprint != other.fingerprint
    assert len(first.fingerprint) == 16


def test_finding_serializes_every_mandated_field():
    finding = Finding(plugin="ssl", title="Weak protocol", severity=Severity.HIGH)
    finding.add_evidence(Evidence(EvidenceKind.TLS, "TLS 1.0 offered"))
    payload = finding.to_dict()

    for key in (
        "confidence",
        "severity",
        "verified",
        "evidence",
        "validation_method",
        "risk_score",
        "exploitability",
        "false_positive_probability",
    ):
        assert key in payload, f"{key} must appear on every finding"


# --- event bus --------------------------------------------------------------


def test_event_bus_delivers_to_topic_and_wildcard():
    bus = events_module.EventBus()
    seen: list[str] = []

    bus.subscribe(events_module.DNS_RESOLVED, lambda e: seen.append("topic"))
    bus.subscribe("*", lambda e: seen.append("wildcard"))
    bus.publish(events_module.DNS_RESOLVED, {"host": "example.com"})

    assert sorted(seen) == ["topic", "wildcard"]


def test_event_bus_isolates_a_failing_subscriber():
    bus = events_module.EventBus()
    delivered: list[str] = []

    def explode(event):
        raise RuntimeError("subscriber is broken")

    bus.subscribe("scan.progress", explode)
    bus.subscribe("scan.progress", lambda e: delivered.append("ok"))
    bus.publish("scan.progress", {"percent": 10})

    # One bad subscriber must never stop the others.
    assert delivered == ["ok"]


def test_event_bus_unsubscribe_stops_delivery():
    bus = events_module.EventBus()
    seen: list[int] = []
    unsubscribe = bus.subscribe("x", lambda e: seen.append(1))

    bus.publish("x", {})
    unsubscribe()
    bus.publish("x", {})

    assert len(seen) == 1


# --- shared cache -----------------------------------------------------------


def test_cache_computes_once_and_then_hits():
    cache = cache_module.SharedCache()
    calls: list[int] = []

    def compute():
        calls.append(1)
        return "93.184.216.34"

    first = cache.get_or_compute("dns", "example.com", compute)
    second = cache.get_or_compute("dns", "example.com", compute)

    assert first == second == "93.184.216.34"
    assert len(calls) == 1, "a cached lookup must not be repeated"
    assert cache.stats.hits == 1


def test_cache_coalesces_concurrent_callers():
    """Ten threads asking for the same key must produce exactly one request."""
    cache = cache_module.SharedCache()
    calls: list[int] = []
    lock = threading.Lock()

    def slow_compute():
        with lock:
            calls.append(1)
        time.sleep(0.05)
        return "value"

    results: list[str] = []
    threads = [
        threading.Thread(
            target=lambda: results.append(cache.get_or_compute("http", "/", slow_compute))
        )
        for _ in range(10)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(calls) == 1, "single-flight coalescing failed"
    assert results == ["value"] * 10


def test_cache_namespaces_do_not_collide():
    cache = cache_module.SharedCache()
    cache.set("dns", "example.com", "A-record")
    cache.set("tls", "example.com", "cert")

    assert cache.get("dns", "example.com") == "A-record"
    assert cache.get("tls", "example.com") == "cert"


# --- confidence engine ------------------------------------------------------


def test_single_weak_indicator_stays_below_the_reporting_threshold():
    """The brief's core rule: never trust one indicator."""
    finding = Finding(plugin="siem", title="Wazuh detected", severity=Severity.MEDIUM)
    finding.add_evidence(Evidence(EvidenceKind.HTML, "Page title mentions Wazuh"))
    confidence_module.score_finding(finding)

    assert finding.confidence < confidence_module.REPORTING_THRESHOLD
    assert finding.suppressed is True
    assert finding.verified is False


def test_many_diverse_indicators_clear_the_threshold():
    finding = Finding(
        plugin="siem",
        title="Wazuh detected",
        severity=Severity.MEDIUM,
        validation_method=ValidationMethod.MULTI_INDICATOR,
    )
    for kind, summary in (
        (EvidenceKind.FAVICON, "Favicon hash matches Wazuh"),
        (EvidenceKind.HTML, "Login page title is Wazuh"),
        (EvidenceKind.API, "/security/user/authenticate responded"),
        (EvidenceKind.JS, "Bundle references wazuh-app"),
        (EvidenceKind.HEADER, "Server header matches"),
    ):
        finding.add_evidence(Evidence(kind, summary))
    confidence_module.score_finding(finding)

    assert finding.confidence > confidence_module.REPORTING_THRESHOLD
    assert finding.suppressed is False
    assert finding.false_positive_probability < 0.2


def test_repeated_evidence_of_one_kind_is_worth_less_than_diverse_evidence():
    repeated = Finding(plugin="http", title="Repeated", severity=Severity.MEDIUM)
    for index in range(5):
        repeated.add_evidence(Evidence(EvidenceKind.HTML, f"match {index}"))
    confidence_module.score_finding(repeated)

    diverse = Finding(plugin="http", title="Diverse", severity=Severity.MEDIUM)
    for kind in (
        EvidenceKind.HEADER,
        EvidenceKind.DNS,
        EvidenceKind.TLS,
        EvidenceKind.API,
        EvidenceKind.JS,
    ):
        diverse.add_evidence(Evidence(kind, "match"))
    confidence_module.score_finding(diverse)

    assert diverse.confidence > repeated.confidence


def test_finding_with_no_evidence_is_never_reported():
    finding = Finding(plugin="guess", title="Hunch", severity=Severity.CRITICAL)
    confidence_module.score_finding(finding)

    assert finding.confidence == pytest.approx(0.0, abs=1.0)
    assert finding.suppressed is True


def test_risk_score_reflects_severity_and_exploitability():
    low = Finding(plugin="a", title="a", severity=Severity.LOW)
    high = Finding(plugin="b", title="b", severity=Severity.CRITICAL)
    for finding in (low, high):
        for kind in (EvidenceKind.HEADER, EvidenceKind.DNS, EvidenceKind.TLS):
            finding.add_evidence(Evidence(kind, "observed"))
        confidence_module.score_finding(finding)

    assert high.risk_score > low.risk_score


def test_aggregate_risk_is_bounded():
    findings = []
    for index in range(30):
        finding = Finding(plugin="x", title=f"t{index}", severity=Severity.CRITICAL)
        for kind in (EvidenceKind.HEADER, EvidenceKind.DNS, EvidenceKind.TLS):
            finding.add_evidence(Evidence(kind, "observed"))
        confidence_module.score_finding(finding)
        findings.append(finding)

    assert 0.0 <= confidence_module.aggregate_risk(findings) <= 100.0


# --- fingerprinting ---------------------------------------------------------


def test_detects_nextjs_from_headers_and_body():
    observation = fingerprint.Observation(
        url="https://example.com",
        status_code=200,
        headers={"x-powered-by": "Next.js", "server": "cloudflare"},
        body='<div id="__next"></div><script src="/_next/static/chunks/main.js"></script>',
    )
    names = {tech.name for tech in fingerprint.detect_technologies(observation)}

    assert "Next.js" in names
    assert "Cloudflare" in names


def test_detects_server_version():
    observation = fingerprint.Observation(headers={"server": "nginx/1.24.0"}, status_code=200)
    nginx = [t for t in fingerprint.detect_technologies(observation) if t.name == "nginx"]

    assert nginx and nginx[0].version == "1.24.0"


def test_static_export_classifies_as_static_site():
    observation = fingerprint.Observation(
        url="https://example.com",
        status_code=200,
        headers={"server": "cloudflare", "cf-ray": "abc123"},
        body='<div id="__next"></div>',
    )
    technologies = fingerprint.detect_technologies(observation)
    surface, reasons = fingerprint.classify_surface(observation, technologies)

    assert surface in (Surface.STATIC_SITE, Surface.SPA, Surface.CDN_EDGE)
    assert reasons, "the classification must explain itself"


# --- technology-aware selection --------------------------------------------


def _tech(name: str, category: str = "framework") -> Technology:
    return Technology(name=name, category=category, confidence=95.0)


def test_nextjs_static_site_skips_impossible_php_and_cms_checks():
    plan = selection.build_plan(
        candidates=["dns", "http", "webapp", "database", "siem", "honeypot", "ids"],
        technologies=[_tech("Next.js"), _tech("Cloudflare", "cdn")],
        surface=Surface.STATIC_SITE,
    )
    skipped = {decision.plugin for decision in plan.skipped}

    assert {"siem", "honeypot", "ids"} <= skipped
    assert "dns" in plan.selected
    assert "http" in plan.selected
    for decision in plan.skipped:
        assert decision.reason, "every skip must be explained"


def test_dynamic_php_app_enables_server_side_checks():
    plan = selection.build_plan(
        candidates=["dns", "http", "webapp", "database", "dirs"],
        technologies=[_tech("PHP", "language"), _tech("Apache", "server")],
        surface=Surface.DYNAMIC_APP,
        active=True,
    )

    assert "webapp" in plan.selected


def test_active_only_plugins_are_skipped_in_passive_mode():
    plan = selection.build_plan(
        candidates=["ports", "dirs", "dns"],
        technologies=[],
        surface=Surface.DYNAMIC_APP,
        active=False,
    )

    assert "dns" in plan.selected
    assert "ports" not in plan.selected


def test_force_all_overrides_every_gate():
    plan = selection.build_plan(
        candidates=["siem", "honeypot", "ids"],
        technologies=[_tech("Next.js")],
        surface=Surface.STATIC_SITE,
        active=True,
        force_all=True,
    )

    assert set(plan.selected) == {"siem", "honeypot", "ids"}


def test_always_on_recon_plugins_run_even_with_no_technology_signal():
    plan = selection.build_plan(
        candidates=["dns", "ip", "http", "ssl", "mail"],
        technologies=[],
        surface=Surface.UNKNOWN,
    )

    assert set(plan.selected) == {"dns", "ip", "http", "ssl", "mail"}


def test_exploitability_multipliers_are_ordered():
    assert Exploitability.TRIVIAL.multiplier > Exploitability.THEORETICAL.multiplier

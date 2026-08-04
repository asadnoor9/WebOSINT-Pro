"""Finding normalization, deduplication, confidence and source attribution."""

from core.findings import (
    Finding,
    FindingCollector,
    Severity,
    Status,
    normalize_identifier,
    status_for_confidence,
)
from core.redaction import Redactor


def _collector(untrusted: bool = False) -> FindingCollector:
    return FindingCollector(Redactor(), untrusted=untrusted)


def _finding(**kwargs) -> Finding:
    defaults = {
        "module": "port",
        "category": "open_port",
        "title": "Port 443 open",
        "value": "example.com:443",
        "severity": Severity.INFO,
        "confidence": 0.6,
    }
    defaults.update(kwargs)
    return Finding(**defaults)


def test_normalize_identifier_is_stable_across_formatting():
    assert normalize_identifier("HTTPS://Example.COM:443/Path/") == normalize_identifier(
        "https://example.com:443/Path"
    )
    assert normalize_identifier("  Example.Com  ") == "example-com"
    assert normalize_identifier("example.com.") == "example-com"


def test_identical_findings_are_merged():
    collector = _collector()
    collector.add(_finding())
    collector.add(_finding())
    assert len(collector.all()) == 1
    assert collector.to_dict()["duplicates_merged"] == 1


def test_same_finding_from_two_modules_merges_sources_and_boosts_confidence():
    collector = _collector()
    collector.add(_finding(module="port", confidence=0.6))
    collector.add(_finding(module="http", confidence=0.6))
    findings = collector.all()
    assert len(findings) == 1
    assert set(findings[0].sources) == {"port", "http"}
    assert findings[0].confidence > 0.6


def test_dedup_key_is_module_independent():
    assert _finding(module="port").key == _finding(module="http").key


def test_distinct_identifiers_are_not_merged():
    collector = _collector()
    collector.add(_finding(value="example.com:443"))
    collector.add(_finding(value="example.com:80"))
    assert len(collector.all()) == 2


def test_fingerprint_is_deterministic():
    assert _finding().fingerprint == _finding().fingerprint
    assert _finding().fingerprint != _finding(value="example.com:80").fingerprint


def test_status_labels_follow_confidence():
    assert status_for_confidence(0.99) == Status.CONFIRMED
    assert status_for_confidence(0.8) == Status.LIKELY
    assert status_for_confidence(0.5) == Status.POSSIBLE
    assert status_for_confidence(0.1) == Status.UNVERIFIED


def test_untrusted_mode_labels_every_finding():
    collector = _collector(untrusted=True)
    collector.add(_finding())
    assert collector.all()[0].status == Status.UNTRUSTED


def test_actionable_filters_out_informational_findings():
    collector = _collector()
    collector.add(_finding(value="a", severity=Severity.INFO))
    collector.add(_finding(value="b", severity=Severity.HIGH))
    actionable = collector.actionable(Severity.LOW)
    assert len(actionable) == 1
    assert actionable[0].severity == Severity.HIGH


def test_merge_keeps_the_highest_severity():
    collector = _collector()
    collector.add(_finding(severity=Severity.LOW))
    collector.add(_finding(severity=Severity.CRITICAL))
    assert collector.all()[0].severity == Severity.CRITICAL


def test_ordering_is_deterministic_by_severity_then_key():
    collector = _collector()
    for value, severity in [
        ("z", Severity.LOW),
        ("a", Severity.CRITICAL),
        ("m", Severity.LOW),
        ("b", Severity.CRITICAL),
    ]:
        collector.add(_finding(value=value, severity=severity, confidence=0.6))
    order = [(f.severity.value, f.value) for f in collector.all()]
    assert order == [
        ("critical", "a"),
        ("critical", "b"),
        ("low", "m"),
        ("low", "z"),
    ]
    assert order == [(f.severity.value, f.value) for f in collector.all()]


def test_severity_counts_in_summary():
    collector = _collector()
    collector.add(_finding(value="a", severity=Severity.HIGH))
    collector.add(_finding(value="b", severity=Severity.HIGH))
    collector.add(_finding(value="c", severity=Severity.LOW))
    counts = collector.to_dict()["severity_counts"]
    assert counts["high"] == 2
    assert counts["low"] == 1


def test_evidence_is_combined_on_merge():
    collector = _collector()
    collector.add(_finding(evidence="banner observed"))
    collector.add(_finding(evidence="tls handshake"))
    evidence = collector.all()[0].evidence
    assert "banner observed" in evidence
    assert "tls handshake" in evidence

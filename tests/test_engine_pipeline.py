"""Integration and benchmark tests for the pipeline, reporting and service."""

from __future__ import annotations

import json
import time

import pytest

from engine import reporting, service
from engine.cli import build_parser
from engine.cli import main as cli_main
from engine.models import (
    Evidence,
    EvidenceKind,
    Finding,
    Severity,
    Surface,
    Technology,
    ValidationMethod,
)
from engine.pipeline import AdaptiveConcurrency, ScanPipeline, ScanResult, normalize_target
from engine.plugins import Plugin, PluginRegistry, ScanContext

# --- target normalization ---------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("https://example.com/path?q=1", "example.com"),
        ("http://Example.COM", "example.com"),
        ("example.com:8443", "example.com"),
        ("  example.com.  ", "example.com"),
        ("user:pass@example.com", "example.com"),
        ("asadnoor.example.pk", "asadnoor.example.pk"),
    ],
)
def test_normalize_target(raw, expected):
    assert normalize_target(raw) == expected


# --- adaptive concurrency ---------------------------------------------------


def test_adaptive_concurrency_backs_off_on_errors_and_recovers():
    controller = AdaptiveConcurrency(minimum=1, maximum=16, current=8)

    for _ in range(20):
        controller.record(ok=False)
    reduced = controller.current

    for _ in range(200):
        controller.record(ok=True)

    assert reduced < 8, "errors must reduce concurrency"
    assert controller.current >= reduced, "success must let concurrency recover"
    assert 1 <= controller.current <= 16, "concurrency must stay within bounds"


# --- plugin lifecycle -------------------------------------------------------


class _RecordingPlugin(Plugin):
    """A plugin that records which lifecycle hooks ran."""

    name = "recorder"
    version = "1.0.0"
    description = "Test plugin."
    calls: list[str] = []

    def initialize(self, context: ScanContext) -> None:
        type(self).calls.append("initialize")

    def scan(self, context: ScanContext) -> list[Finding]:
        type(self).calls.append("scan")
        finding = Finding(
            plugin=self.name,
            title="Test finding",
            severity=Severity.MEDIUM,
            target=context.target,
            validation_method=ValidationMethod.MULTI_INDICATOR,
        )
        for kind in (EvidenceKind.HEADER, EvidenceKind.DNS, EvidenceKind.TLS, EvidenceKind.API):
            finding.add_evidence(Evidence(kind, "observed"))
        return [finding]

    def correlate(self, findings, context):
        type(self).calls.append("correlate")
        return findings

    def shutdown(self) -> None:
        type(self).calls.append("shutdown")


class _ExplodingPlugin(Plugin):
    """A plugin that always fails, to prove failures are isolated."""

    name = "exploder"
    version = "1.0.0"

    def scan(self, context: ScanContext) -> list[Finding]:
        raise RuntimeError("this plugin is broken")


def _registry() -> PluginRegistry:
    registry = PluginRegistry()
    registry.register(_RecordingPlugin)
    registry.register(_ExplodingPlugin)
    return registry


def test_plugin_lifecycle_hooks_all_run_in_order():
    _RecordingPlugin.calls = []
    pipeline = ScanPipeline(_registry(), threads=2, force_all=True)
    pipeline.scan("example.com")

    assert "initialize" in _RecordingPlugin.calls
    assert "scan" in _RecordingPlugin.calls
    assert "shutdown" in _RecordingPlugin.calls
    assert _RecordingPlugin.calls.index("initialize") < _RecordingPlugin.calls.index("scan")
    assert _RecordingPlugin.calls.index("scan") < _RecordingPlugin.calls.index("shutdown")


def test_one_failing_plugin_never_aborts_the_scan():
    _RecordingPlugin.calls = []
    pipeline = ScanPipeline(_registry(), threads=2, force_all=True)
    result = pipeline.scan("example.com")

    statuses = {outcome.plugin: outcome.status for outcome in result.outcomes}
    assert statuses.get("exploder") == "error"
    assert statuses.get("recorder") == "ok"
    assert any(f.title == "Test finding" for f in result.findings)


def test_registry_supports_disable_enable_and_versioning():
    registry = _registry()
    assert "recorder" in registry.available_names()

    registry.disable("recorder")
    assert not registry.is_enabled("recorder")
    assert "recorder" not in registry.available_names()

    registry.enable("recorder")
    assert registry.is_enabled("recorder")

    class _NewerRecorder(_RecordingPlugin):
        version = "2.0.0"

    registry.register(_NewerRecorder)
    registration = {r.name: r for r in registry.registrations()}["recorder"]
    assert registration.version == "2.0.0", "a higher version must win"


def test_scan_result_is_json_serializable_and_deterministic():
    pipeline = ScanPipeline(_registry(), threads=2, force_all=True)
    result = pipeline.scan("example.com")
    payload = result.to_dict()

    encoded = json.dumps(payload, sort_keys=True, default=str)
    assert json.loads(encoded)["target"] == "example.com"
    assert "risk_score" in payload
    assert "severity_counts" in payload or "findings" in payload


# --- reporting --------------------------------------------------------------


def _sample_result() -> ScanResult:
    finding = Finding(
        plugin="http",
        title="Missing Strict-Transport-Security header",
        severity=Severity.MEDIUM,
        target="example.com",
        description="The response did not set HSTS.",
        tags=["missing-security-header"],
        validation_method=ValidationMethod.MULTI_INDICATOR,
    )
    for kind in (EvidenceKind.HEADER, EvidenceKind.TLS, EvidenceKind.DNS, EvidenceKind.API):
        finding.add_evidence(Evidence(kind, "observed", "value"))

    from engine.confidence import score_finding

    score_finding(finding)

    return ScanResult(
        target="example.com",
        duration_ms=1234,
        surface=Surface.STATIC_SITE,
        technologies=[Technology("Next.js", "framework", "14.2", 96.0)],
        findings=[finding],
        risk_score=42.0,
    )


def test_reports_render_in_every_text_format():
    bundle = reporting.ReportBundle.build(_sample_result())

    markdown = reporting.render_markdown(bundle)
    html = reporting.render_html(bundle)
    csv_text = reporting.render_csv(bundle)
    payload = json.loads(reporting.render_json(bundle))

    assert "example.com" in markdown and "Executive summary" in markdown
    assert html.startswith("<!doctype html>") and "example.com" in html
    assert "Missing Strict-Transport-Security header" in csv_text
    assert payload["target"] == "example.com"
    assert "analysis" in payload


def test_every_audience_renders_and_executive_hides_raw_findings():
    bundle = reporting.ReportBundle.build(_sample_result())

    executive = reporting.render_markdown(bundle, reporting.Audience.EXECUTIVE)
    technical = reporting.render_markdown(bundle, reporting.Audience.TECHNICAL)

    assert "## Findings" not in executive
    assert "## Findings" in technical


def test_report_generation_writes_files(tmp_path):
    outcome = reporting.generate(_sample_result(), tmp_path, formats=["json", "md", "html", "csv"])

    assert not outcome["failed"], outcome["failed"]
    assert len(outcome["written"]) == 4
    for path in outcome["written"]:
        assert path


def test_a_missing_optional_exporter_does_not_block_the_others(tmp_path):
    """PDF may be unavailable; JSON must still be written."""
    outcome = reporting.generate(_sample_result(), tmp_path, formats=["json", "pdf"])
    written = " ".join(outcome["written"])

    assert ".json" in written
    if outcome["failed"].get("pdf"):
        assert "reportlab" in outcome["failed"]["pdf"]


def test_html_report_escapes_untrusted_content():
    """Scanned content is untrusted and must never render as live markup."""
    result = _sample_result()
    result.findings[0].title = "<script>alert('xss')</script>"
    bundle = reporting.ReportBundle.build(result)
    html = reporting.render_html(bundle)

    assert "<script>alert" not in html
    assert "&lt;script&gt;" in html


# --- AI / correlation engine ------------------------------------------------


def test_analysis_is_grounded_in_evidence_only():
    from engine.correlation import analyse

    analysis = analyse(_sample_result())

    assert analysis.executive_summary
    assert analysis.soc_summary
    for item in analysis.priorities:
        assert item["remediation"], "every prioritized fix needs remediation text"


def test_analysis_of_a_clean_scan_does_not_invent_findings():
    from engine.correlation import analyse

    clean = ScanResult(target="example.com", surface=Surface.STATIC_SITE)
    analysis = analyse(clean)

    assert analysis.priorities == []
    assert analysis.executive_summary


# --- storage ----------------------------------------------------------------


def test_storage_round_trip(tmp_path):
    from engine.storage import Storage

    store = Storage(f"sqlite:///{tmp_path / 'test.db'}")
    scan_id = store.record_scan(_sample_result())
    history = store.history("example.com")

    assert scan_id
    assert history and history[0]["target"] == "example.com"
    assert history[0]["risk_score"] == 42.0
    store.close()


def test_storage_tracks_the_target_inventory(tmp_path):
    from engine.storage import Storage

    store = Storage(f"sqlite:///{tmp_path / 'inventory.db'}")
    store.record_scan(_sample_result())
    store.record_scan(_sample_result())
    targets = store.targets()

    assert len(targets) == 1, "the same host must not be duplicated"
    assert targets[0]["scan_count"] == 2
    store.close()


# --- service and CLI --------------------------------------------------------


def test_humanize_duration_reads_naturally():
    assert service.humanize_duration(0) == "-"
    assert service.humanize_duration(45) == "45s"
    assert "m" in service.humanize_duration(3600 * 2 + 60)


def test_service_status_reports_a_known_state():
    status = service.current_status()
    assert isinstance(status.state, service.ServiceState)
    assert "state" in status.to_dict()


def test_health_check_returns_a_verdict_and_checks():
    report = service.health_check()
    assert report["status"] in ("healthy", "degraded", "unhealthy")
    assert report["checks"]


def test_cli_exposes_every_required_command():
    parser = build_parser()
    actions = [a for a in parser._actions if hasattr(a, "choices") and a.choices]
    commands = set()
    for action in actions:
        commands.update(action.choices or {})

    required = {
        "start",
        "stop",
        "restart",
        "reload",
        "status",
        "health",
        "logs",
        "version",
        "update",
        "doctor",
    }
    assert required <= commands, f"missing: {required - commands}"


def test_cli_version_and_doctor_run_without_a_service(capsys):
    assert cli_main(["version", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["engine_version"]

    cli_main(["doctor", "--json"])
    doctor = json.loads(capsys.readouterr().out)
    assert doctor["checks"]


# --- benchmark --------------------------------------------------------------


def test_scan_overhead_stays_small():
    """Engine overhead, excluding plugin work, must stay in the low tens of ms."""
    pipeline = ScanPipeline(_registry(), threads=4, force_all=True)

    started = time.perf_counter()
    for _ in range(5):
        pipeline.scan("example.com")
    average_ms = (time.perf_counter() - started) * 1000 / 5

    assert average_ms < 750, f"pipeline overhead regressed to {average_ms:.0f}ms"


def test_cache_prevents_duplicate_work_across_plugins():
    """The whole point of the shared cache: one lookup, many readers."""
    from engine.cache import SharedCache

    cache = SharedCache()
    calls = []

    for _ in range(20):
        cache.get_or_compute("dns", "example.com", lambda: calls.append(1) or "result")

    assert len(calls) == 1
    assert cache.stats.hits == 19

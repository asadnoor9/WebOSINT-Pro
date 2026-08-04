"""Output behaviour: quiet defaults, deterministic ordering, machine-readable JSON."""

import json
import logging

from core.findings import Finding, FindingCollector, Severity
from core.logger import RedactionFilter, console_level, setup_logger
from core.redaction import Redactor


def test_console_levels_map_to_verbosity():
    assert console_level(quiet=True) == logging.ERROR
    assert console_level(0) == logging.WARNING
    assert console_level(1) == logging.INFO
    assert console_level(2) == logging.DEBUG


def test_logger_does_not_write_files_when_disabled(tmp_path):
    setup_logger(log_dir=str(tmp_path), session_id="t1", write_files=False)
    assert list(tmp_path.iterdir()) == []


def test_logger_writes_redacted_json_lines(tmp_path):
    log = setup_logger(verbose=1, log_dir=str(tmp_path), session_id="t2", write_files=True)
    log.info("token api_key=SECRETVALUE123456 for /home/analyst/scan")
    for handler in log.handlers:
        handler.flush()

    files = list(tmp_path.glob("*.jsonl"))
    assert files
    content = files[0].read_text(encoding="utf-8")
    assert "SECRETVALUE123456" not in content
    assert json.loads(content.splitlines()[0])["level"] == "INFO"


def test_redaction_filter_strips_exception_info():
    record = logging.LogRecord(
        "webosint", logging.ERROR, __file__, 1, "api_key=ABCDEF1234567890", (), None
    )
    RedactionFilter(Redactor()).filter(record)
    assert "ABCDEF1234567890" not in record.getMessage()
    assert record.exc_info is None


def _finding(value: str, severity: Severity) -> Finding:
    return Finding(
        module="test",
        category="issue",
        title=f"Issue {value}",
        value=value,
        severity=severity,
        confidence=0.9,
    )


def test_json_output_is_stable_and_serializable():
    collector = FindingCollector(Redactor())
    for value, severity in [("b", Severity.HIGH), ("a", Severity.HIGH), ("c", Severity.LOW)]:
        collector.add(_finding(value, severity))

    first = json.dumps(collector.to_dict(), sort_keys=True)
    second = json.dumps(collector.to_dict(), sort_keys=True)
    assert first == second

    payload = json.loads(first)
    assert payload["total"] == 3
    assert [f["value"] for f in payload["findings"]] == ["a", "b", "c"]


def test_finding_dict_exposes_attribution_fields():
    finding = Finding(
        module="http",
        category="header",
        title="Example",
        value="example.com",
        severity=Severity.MEDIUM,
        confidence=0.75,
        evidence="header observed",
    )
    payload = finding.to_dict()
    for field in ("id", "category", "severity", "confidence", "sources", "status", "evidence"):
        assert field in payload
    assert payload["sources"] == ["http"]
    assert payload["status"] == "likely"


def test_report_payload_redacts_secrets():
    collector = FindingCollector(Redactor())
    collector.add(
        Finding(
            module="http",
            category="header",
            title="Auth header",
            value="api_key=SUPERSECRETVALUE123",
            severity=Severity.LOW,
            confidence=0.9,
        )
    )
    assert "SUPERSECRETVALUE123" not in json.dumps(collector.to_dict())

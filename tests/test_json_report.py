"""Tests for report generation and redaction."""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from reports.json_report import JSONReport  # noqa: E402
from reports.markdown_report import MarkdownReport  # noqa: E402
from reports.html_report import HTMLReport  # noqa: E402
from core.version import __version__  # noqa: E402


def _results():
    return {
        "meta": {"target": "example.com", "mode": "medium"},
        "summary": {"total_findings": 1, "risk_counts": {"medium": 1},
                    "modules_run": 1, "errors": 0},
        "findings": {
            "http": {
                "module": "http",
                "findings": [
                    {"title": "Leak at 192.168.1.50", "risk": "medium",
                     "detail": "seen on host 192.168.1.50", "evidence": {}}
                ],
                "data": {},
                "error": None,
            }
        },
        "errors": {},
    }


def test_json_report_version_and_redaction(tmp_path):
    path = str(tmp_path / "r.json")
    JSONReport(_results(), redact=True).save(path)
    with open(path) as fh:
        data = json.load(fh)
    assert data["version"] == __version__
    blob = json.dumps(data)
    assert "192.168.1.50" not in blob
    assert "[redacted-ip]" in blob


def test_markdown_report(tmp_path):
    path = str(tmp_path / "r.md")
    MarkdownReport(_results(), redact=True).save(path)
    text = open(path).read()
    assert "192.168.1.50" not in text
    assert __version__ in text


def test_html_report(tmp_path):
    path = str(tmp_path / "r.html")
    HTMLReport(_results(), redact=True).save(path)
    text = open(path).read()
    assert "192.168.1.50" not in text
    assert "v" + __version__ in text
    assert "font-family" in text

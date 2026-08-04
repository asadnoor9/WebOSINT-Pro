"""Tests for the merged reporting package.

Replaces the obsolete tests/test_json_report.py, which called constructor
keywords (``redact=``) that were removed several releases ago and had been
failing in CI ever since.
"""

from __future__ import annotations

import json as jsonlib
import stat

import pytest

from core import paths
from reporting import export
from reporting.base import BaseReport
from reporting.csv import CSVReport
from reporting.html import HTMLReport
from reporting.json import JSONReport
from reporting.markdown import MarkdownReport

RESULTS = {
    "meta": {
        "target": "example.com",
        "profile": "safe",
        "session_id": "testsession",
        "mode": "passive",
        "detail_level": "standard",
    },
    "summary": {
        "total_findings": 1,
        "risk_counts": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
    },
    "findings": {"dns": {"records": {"A": ["203.0.113.10"]}}},
    "normalized_findings": [
        {
            "category": "dns",
            "title": "A record",
            "value": "203.0.113.10",
            "severity": "high",
            "confidence": 95,
            "status": "verified",
            "sources": ["dns"],
        }
    ],
    "errors": {},
}

LIGHT_WRITERS = [JSONReport, HTMLReport, MarkdownReport, CSVReport]


# --------------------------------------------------------------- base class


def test_every_writer_subclasses_base():
    for writer in LIGHT_WRITERS:
        assert issubclass(writer, BaseReport)
        assert writer.extension, f"{writer.__name__} declares no extension"
        assert writer.format_name, f"{writer.__name__} declares no format name"


def test_base_holds_results_for_every_writer():
    for writer in LIGHT_WRITERS:
        assert writer(RESULTS).results is RESULTS
        assert writer(None).results == {}


def test_default_stem_is_filesystem_safe():
    stem = BaseReport.default_stem("sub.example.com/path?q=1")
    assert "/" not in stem and "?" not in stem and "." not in stem
    assert stem.startswith("webosint_sub_example_com")


def test_default_stem_survives_an_empty_target():
    assert BaseReport.default_stem("").startswith("webosint_target_")


def test_filename_uses_the_declared_extension():
    assert JSONReport(RESULTS).filename("scan") == "scan.json"
    assert MarkdownReport(RESULTS).filename("scan") == "scan.md"


def test_write_creates_parents_and_restricts_permissions(tmp_path):
    destination = tmp_path / "nested" / "deeper" / "scan.json"
    written = JSONReport(RESULTS).write(destination)

    assert destination.exists(), "write() must create missing parent directories"
    assert written == str(destination)
    mode = stat.S_IMODE(destination.stat().st_mode)
    assert mode == 0o600, f"reports contain evidence and must be owner-only, got {oct(mode)}"


# ------------------------------------------------------------ light writers


@pytest.mark.parametrize("writer", LIGHT_WRITERS, ids=lambda w: w.format_name)
def test_writer_produces_a_non_empty_file(writer, tmp_path):
    path = tmp_path / writer(RESULTS).filename("scan")
    writer(RESULTS).write(path)
    assert path.read_text(encoding="utf-8").strip()


@pytest.mark.parametrize("writer", LIGHT_WRITERS, ids=lambda w: w.format_name)
def test_writer_tolerates_empty_results(writer, tmp_path):
    path = tmp_path / writer({}).filename("empty")
    writer({}).write(path)
    assert path.exists()


def test_json_report_is_valid_json_and_carries_the_target(tmp_path):
    path = tmp_path / "scan.json"
    JSONReport(RESULTS).write(path)
    payload = jsonlib.loads(path.read_text(encoding="utf-8"))

    assert payload["meta"]["target"] == "example.com"
    for section in ("summary", "findings", "enrichment", "errors"):
        assert section in payload


def test_html_report_escapes_and_reports_the_target(tmp_path):
    path = tmp_path / "scan.html"
    HTMLReport(RESULTS).write(path)
    body = path.read_text(encoding="utf-8")
    assert "example.com" in body
    assert "<html" in body.lower()


def test_csv_report_has_a_header_row_per_finding(tmp_path):
    path = tmp_path / "scan.csv"
    CSVReport(RESULTS).write(path)
    rows = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(rows) >= 2, "expected a header plus at least one finding"
    assert "severity" in rows[0]


# ------------------------------------------------------------ format export


def test_resolve_formats_expands_groups():
    assert export.resolve_formats("both") == ["json", "html"]
    assert export.resolve_formats("none") == []
    assert export.resolve_formats("all")[:2] == ["json", "html"]
    assert set(export.resolve_formats("all")) == set(export.WRITERS)


def test_resolve_formats_defaults_to_json():
    assert export.resolve_formats(None) == ["json"]


def test_resolve_formats_deduplicates_and_preserves_order():
    assert export.resolve_formats(["html", "json", "html"]) == ["html", "json"]


def test_resolve_formats_drops_unknown_names_instead_of_raising():
    assert export.resolve_formats("telepathy") == []
    assert export.resolve_formats(["json", "telepathy"]) == ["json"]


def test_writer_for_rejects_unknown_formats():
    with pytest.raises(ValueError):
        export.writer_for("telepathy")


def test_write_reports_writes_each_requested_format(tmp_path):
    written = export.write_reports(RESULTS, tmp_path, formats="both", stem="scan")
    assert sorted(p.rsplit(".", 1)[1] for p in written) == ["html", "json"]
    assert (tmp_path / "scan.json").exists()
    assert (tmp_path / "scan.html").exists()


def test_write_reports_returns_nothing_for_none(tmp_path):
    assert export.write_reports(RESULTS, tmp_path, formats="none") == []
    assert not list(tmp_path.iterdir())


def test_write_reports_derives_a_stem_from_the_target(tmp_path):
    written = export.write_reports(RESULTS, tmp_path, formats="json")
    assert len(written) == 1
    assert "webosint_example_com" in written[0]


def test_one_failing_writer_does_not_block_the_others(tmp_path, monkeypatch):
    class Exploding(BaseReport):
        extension = "boom"
        format_name = "Boom"

        def save(self, path: str) -> str:
            raise RuntimeError("missing optional dependency")

    monkeypatch.setitem(export.WRITERS, "boom", lambda: Exploding)
    monkeypatch.setitem(export.GROUPS, "pair", ("boom", "json"))

    written = export.write_reports(RESULTS, tmp_path, formats="pair", stem="scan")
    assert written == [str(tmp_path / "scan.json")]


# -------------------------------------------------------------- output paths


def test_runtime_paths_all_live_under_output():
    root = paths.output_dir()
    assert root.name == "output"
    for resolved in (paths.reports_dir(), paths.logs_dir(), paths.cache_dir()):
        assert resolved.parent == root


def test_output_root_is_relocatable(monkeypatch, tmp_path):
    monkeypatch.setenv(paths.OUTPUT_DIR_ENV, str(tmp_path / "elsewhere"))
    assert paths.reports_dir() == tmp_path / "elsewhere" / "reports"


def test_ensure_all_creates_the_tree(monkeypatch, tmp_path):
    monkeypatch.setenv(paths.OUTPUT_DIR_ENV, str(tmp_path / "tree"))
    created = paths.ensure_all()
    for key in ("output", "reports", "logs", "cache"):
        assert created[key].is_dir()

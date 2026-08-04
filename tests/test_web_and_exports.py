"""Tests for the new export formats and the web interface safety gate.

Nothing here touches the network. The web tests exercise the request-handling
logic directly so they run without Flask installed.
"""

from __future__ import annotations

import csv
from pathlib import Path

import pytest

from core.cli import parse_args
from core.config import Config
from core.paths import reports_dir
from reporting.csv import CSVReport
from web.app import authorize, build_config

RESULTS = {
    "meta": {"target": "example.com", "mode": "passive"},
    "summary": {"total_findings": 2},
    "normalized_findings": [
        {
            "category": "dns",
            "title": "A record",
            "value": "93.184.216.34",
            "severity": "info",
            "confidence": 0.9,
            "status": "confirmed",
            "sources": ["dns"],
            "evidence": "resolved",
        },
        {
            "category": "tls",
            "title": "Weak cipher",
            "value": ["TLS_RSA", "CBC"],
            "severity": "medium",
            "confidence": 0.6,
            "status": "likely",
            "sources": ["ssl", "http"],
            "evidence": "handshake",
        },
    ],
    "findings": {},
    "errors": {},
}


class FakeForm:
    """Minimal stand-in for a Werkzeug MultiDict."""

    def __init__(self, data: dict):
        self._data = data

    def get(self, key, default=None):
        value = self._data.get(key, default)
        return value[0] if isinstance(value, list) else value

    def getlist(self, key):
        value = self._data.get(key, [])
        return value if isinstance(value, list) else [value]


def base_form(**overrides):
    data = {
        "target": "example.com",
        "confirm_target": "example.com",
        "authorized": "on",
        "profile": "safe",
        "detail": "standard",
    }
    data.update(overrides)
    return FakeForm(data)


# ── CSV export ────────────────────────────────────────────────────────────────


def test_csv_report_has_one_row_per_finding(tmp_path):
    path = str(tmp_path / "out.csv")
    CSVReport(RESULTS).save(path)

    with open(path, encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))

    assert len(rows) == 2
    assert rows[0]["title"] == "A record"
    assert rows[0]["target"] == "example.com"
    assert rows[1]["severity"] == "medium"
    # list values are flattened, not repr'd
    assert rows[1]["value"] == "TLS_RSA; CBC"
    assert rows[1]["sources"] == "ssl+http"


def test_csv_report_is_deterministic(tmp_path):
    first = str(tmp_path / "a.csv")
    second = str(tmp_path / "b.csv")
    CSVReport(RESULTS).save(first)
    CSVReport(RESULTS).save(second)
    assert open(first, encoding="utf-8-sig").read() == open(second, encoding="utf-8-sig").read()


# ── Format plumbing ───────────────────────────────────────────────────────────


@pytest.mark.parametrize("fmt", ["json", "html", "markdown", "csv", "docx", "pdf", "all"])
def test_cli_and_config_accept_new_formats(fmt, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    args = parse_args(["-t", "example.com", "--output", fmt])
    assert args.output == fmt
    assert Config(args).report_format == fmt


def test_unknown_format_falls_back_to_json(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    args = parse_args(["-t", "example.com"])
    args.output = "exe"
    assert Config(args).report_format == "json"


# ── Web authorization gate ────────────────────────────────────────────────────


def test_web_requires_authorization_checkbox(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    form = base_form(authorized=None)
    controller, message = authorize(build_config(form, ["json"]))
    assert controller is None
    assert "uthoriz" in message


def test_web_requires_matching_confirmation(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    form = base_form(confirm_target="wrong.com")
    controller, message = authorize(build_config(form, ["json"]))
    assert controller is None
    assert "does not match" in message


def test_web_blocks_internal_targets(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    form = base_form(target="127.0.0.1", confirm_target="127.0.0.1")
    controller, message = authorize(build_config(form, ["json"]))
    assert controller is None
    assert message


def test_web_allows_authorized_public_target(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    controller, _ = authorize(build_config(base_form(), ["json"]))
    assert controller is not None


# ── Web option plumbing ───────────────────────────────────────────────────────


def test_web_defaults_are_passive_and_tls_verified(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cfg = build_config(base_form(), ["json"])
    assert cfg.active is False
    assert cfg.insecure_tls is False
    assert cfg.keep_raw is False
    assert cfg.detail == "standard"


def test_web_active_and_module_selection(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    form = base_form(active="on", modules=["dns", "ssl"])
    cfg = build_config(form, ["json"])
    assert cfg.active is True
    assert "dns" in cfg.modules and "ssl" in cfg.modules


def test_web_multiple_formats_request_all(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    single = build_config(base_form(), ["pdf"])
    assert single.report_format == "pdf"
    multi = build_config(base_form(), ["pdf", "csv"])
    assert multi.report_format == "all"


def test_web_output_dir_is_separate(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cfg = build_config(base_form(), ["json"])
    # The web UI writes under output/reports/web so nothing lands in the
    # repository root. See core.paths for the single path authority.
    assert cfg.output_dir == str(reports_dir() / "web")
    assert Path(cfg.output_dir).parent.parent.name == "output"

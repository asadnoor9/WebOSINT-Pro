"""Tests for scan speed, verbosity, progress, artifacts and the infrastructure view.

Nothing here touches the network, and nothing imports Flask: the web helpers are
exercised directly so the suite runs without the web extra installed.
"""

from __future__ import annotations

import logging
import os

import pytest

from core.infrastructure import (
    build_infrastructure,
    extract_network,
    extract_services,
    extract_web_server,
    parse_product,
)
from core.risk_rollup import (
    count_severities,
    derive_legacy_findings,
    merge_findings,
)
from tests.test_web_and_exports import base_form
from web.app import (
    DEFAULT_SPEED,
    DEFAULT_VERBOSITY,
    SPEED_PRESETS,
    VERBOSITY_LEVELS,
    Job,
    build_config,
    collect_artifacts,
    resolve_speed,
    resolve_verbosity,
)

# ── Speed presets ─────────────────────────────────────────────────────────────


def test_speed_presets_are_ordered_from_quiet_to_noisy():
    threads = [SPEED_PRESETS[k]["threads"] for k in ("slow", "normal", "fast", "turbo")]
    delays = [SPEED_PRESETS[k]["delay"] for k in ("slow", "normal", "fast", "turbo")]
    assert threads == sorted(threads)
    assert delays == sorted(delays, reverse=True)


def test_resolve_speed_falls_back_to_the_default():
    assert resolve_speed("turbo")[0] == "turbo"
    assert resolve_speed("nonsense")[0] == DEFAULT_SPEED
    assert resolve_speed(None)[0] == DEFAULT_SPEED


def test_speed_preset_drives_pacing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    slow = build_config(base_form(speed="slow"), ["json"])
    turbo = build_config(base_form(speed="turbo"), ["json"])

    # Assert on the requested values: the profile applies its own ceiling
    # afterwards, which is deliberate and tested separately below.
    assert slow._cli_threads == SPEED_PRESETS["slow"]["threads"]
    assert turbo._cli_threads == SPEED_PRESETS["turbo"]["threads"]
    assert slow._cli_threads < turbo._cli_threads
    assert slow._cli_rate_limit < turbo._cli_rate_limit
    assert slow._cli_delay > turbo._cli_delay


def test_profile_ceiling_still_wins_over_a_fast_preset(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cfg = build_config(base_form(speed="turbo", profile="safe"), ["json"])
    # Turbo asks for 24 threads; the safe profile refuses to go that loud.
    assert cfg.threads <= SPEED_PRESETS["turbo"]["threads"]
    assert cfg.threads >= 1


def test_explicit_tuning_overrides_the_preset(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cfg = build_config(base_form(speed="turbo", threads="3"), ["json"])
    # A hand-entered value replaces the preset before Config sees it.
    assert cfg._cli_threads == 3


# ── Verbosity ─────────────────────────────────────────────────────────────────


def test_verbosity_levels_increase_detail():
    levels = [VERBOSITY_LEVELS[i]["level"] for i in sorted(VERBOSITY_LEVELS)]
    assert levels == sorted(levels, reverse=True)
    assert VERBOSITY_LEVELS[0]["level"] == logging.ERROR


def test_resolve_verbosity_rejects_junk():
    assert resolve_verbosity("3") == 3
    assert resolve_verbosity("9") == DEFAULT_VERBOSITY
    assert resolve_verbosity(None) == DEFAULT_VERBOSITY


# ── Live log buffer ───────────────────────────────────────────────────────────


def make_job() -> Job:
    return Job(id="test", target="example.com", mode="passive")


def test_log_tail_returns_only_new_lines():
    job = make_job()
    for i in range(5):
        job.add_log("INFO", "00:00:00", "line " + str(i))
    assert len(job.tail(0)) == 5
    assert len(job.tail(3)) == 2
    assert job.tail(5) == []


def test_log_buffer_is_bounded():
    job = make_job()
    for i in range(1200):
        job.add_log("INFO", "00:00:00", "line " + str(i))
    assert len(job.logs) <= 500
    assert job.log_total == 1200
    # A client that fell behind still gets a valid window, never an exception.
    assert len(job.tail(0)) <= 500


def test_progress_is_exposed_to_the_api():
    job = make_job()
    job.set_progress({"percent": 42.0, "completed": 3, "total": 7, "running": ["dns"]})
    payload = job.public()
    assert payload["progress"]["percent"] == 42.0
    assert payload["progress"]["running"] == ["dns"]


# ── Artifacts ─────────────────────────────────────────────────────────────────


def test_collect_artifacts_registers_real_files(tmp_path):
    html = tmp_path / "report.html"
    html.write_text("<html></html>", encoding="utf-8")
    md = tmp_path / "report.md"
    md.write_text("# report", encoding="utf-8")

    artifacts = collect_artifacts([str(html), str(md)], ["html", "markdown"])
    exts = {a["ext"] for a in artifacts}
    assert exts == {"html", "md"}
    assert all(a["size"] > 0 for a in artifacts)


def test_collect_artifacts_ignores_missing_and_unrequested(tmp_path):
    html = tmp_path / "report.html"
    html.write_text("<html></html>", encoding="utf-8")
    ghost = str(tmp_path / "never-written.json")

    # Redacted paths do not exist on disk; they must not be registered.
    assert collect_artifacts([ghost], ["json"]) == []
    # A produced file the operator did not ask for is skipped.
    assert collect_artifacts([str(html)], ["json"]) == []


# ── Risk rollup ───────────────────────────────────────────────────────────────


LEGACY = {
    "http": {
        "_risk_missing_headers": "medium",
        "_risk_header_disclosure": "low",
        "headers": {"Server": "Apache/2.4.65"},
    },
    "mail": {"_risk_no_spf": "high", "_risk_no_dmarc": "high"},
    "dirs": {"_risk_sensitive_paths": "critical"},
}


def test_legacy_risk_markers_become_findings():
    rows = derive_legacy_findings(LEGACY)
    assert len(rows) == 5
    assert {r["severity"] for r in rows} == {"medium", "low", "high", "critical"}
    assert all(r["title"] for r in rows)


def test_severity_counts_are_no_longer_all_zero():
    counts = count_severities(derive_legacy_findings(LEGACY))
    assert counts["critical"] == 1
    assert counts["high"] == 2
    assert counts["medium"] == 1
    assert counts["low"] == 1


def test_merge_prefers_collector_rows_and_drops_duplicates():
    normalized = [{"module": "http", "title": "Missing Headers", "severity": "high"}]
    legacy = derive_legacy_findings({"http": {"_risk_missing_headers": "medium"}})
    merged = merge_findings(normalized, legacy)
    titles = [r["title"].lower() for r in merged]
    assert titles.count("missing headers") == 1
    assert merged[0]["severity"] == "high"


def test_empty_input_is_safe():
    assert derive_legacy_findings({}) == []
    assert count_severities([]) == dict.fromkeys(("critical", "high", "medium", "low", "info"), 0)


# ── Infrastructure ────────────────────────────────────────────────────────────


def test_parse_product_splits_banner_versions():
    assert parse_product("Apache/2.4.65 (Unix) OpenSSL/3.5.5")[1] == "2.4.65"
    assert parse_product("nginx/1.24.0")[1] == "1.24.0"
    assert parse_product("Microsoft-IIS/10.0")[1] == "10.0"


def test_web_server_keeps_the_version_from_the_raw_header():
    findings = {
        "http": {
            # The module-cleaned value loses the version, so the raw header wins.
            "server": "Apache",
            "headers": {
                "Server": "Apache/2.4.65 (Unix) OpenSSL/3.5.5",
                "X-Powered-By": "PHP/8.2.12",
            },
            "status_code": 200,
        }
    }
    web = extract_web_server(findings)
    assert "apache" in web["product"].lower()
    assert web["version"] == "2.4.65"
    assert "PHP/8.2.12" in web["powered_by"]


def test_network_extracts_isp_and_asn():
    findings = {
        "ip": {
            "resolved_ips": ["163.61.25.60"],
            "163.61.25.60": {
                "ip": "163.61.25.60",
                "version": "IPv4",
                "geo": {
                    "isp": "PITC",
                    "org": "Power Information Technology Company",
                    "as": "AS153561 PITC",
                    "country": "Pakistan",
                    "city": "Lahore",
                },
                "blacklisted": False,
            },
        }
    }
    net = extract_network(findings)
    assert net["primary_ip"] == "163.61.25.60"
    assert net["isp"] == "PITC"
    assert "AS153561" in net["asn"]
    assert net["country"] == "Pakistan"


NMAP_STDOUT = """
PORT     STATE SERVICE VERSION
53/tcp   open  domain  Mikrotik dnsd
80/tcp   open  http    Apache httpd 2.4.65 ((Unix) OpenSSL/3.5.5)
443/tcp  open  ssl/http Apache httpd 2.4.65
Device type: general purpose|router
"""


def test_services_are_parsed_from_nmap_output():
    services = extract_services({"ports": {"scanner": "nmap", "nmap_stdout": NMAP_STDOUT}})
    by_port = {s["port"]: s for s in services}
    assert 80 in by_port
    assert by_port[80]["service"] == "http"
    assert "Apache" in by_port[80]["product"]
    assert by_port[53]["state"] == "open"


def test_build_infrastructure_always_returns_the_full_shape():
    infra = build_infrastructure({})
    for key in (
        "network",
        "operating_system",
        "web_server",
        "services",
        "tls",
        "exposed_port_count",
    ):
        assert key in infra
    assert infra["services"] == []
    assert infra["exposed_port_count"] == 0


# -- Template integrity --------------------------------------------------------

TEMPLATE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web", "templates"
)
TEMPLATES = ["index.html", "jobs.html", "results.html"]


def _template(name: str) -> str:
    with open(os.path.join(TEMPLATE_DIR, name), encoding="utf-8") as handle:
        return handle.read()


@pytest.mark.parametrize("name", TEMPLATES)
def test_templates_have_no_placeholder_leftovers(name):
    """No unconverted placeholder brackets should survive into a template."""
    assert "[[" not in _template(name)


@pytest.mark.parametrize("name", TEMPLATES)
def test_templates_reference_the_favicon(name):
    assert 'rel="icon"' in _template(name)


def test_favicon_file_exists():
    icon = os.path.join(os.path.dirname(TEMPLATE_DIR), "static", "favicon.svg")
    assert os.path.exists(icon)


def test_results_script_brackets_are_balanced():
    """Guard against the brace mangling that once broke the results page.

    A stray closing sequence where an array close belonged was a JavaScript
    syntax error. The whole script failed to parse, so the poller never started
    and the page sat on "Starting..." while the scan ran fine in the background.
    """
    script = _template("results.html").split("<script>")[1].split("</script>")[0]
    assert "}});" not in script
    for opener, closer in (("(", ")"), ("[", "]")):
        assert script.count(opener) == script.count(closer)

"""Organizational-domain mail scoping and background-process helpers."""

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import daemon as daemonlib  # noqa: E402

# --- Registrable domain resolution -----------------------------------------

dns = pytest.importorskip("dns.resolver", reason="dnspython not installed")
from modules.mail_module import registrable_domain  # noqa: E402


@pytest.mark.parametrize(
    "host,expected",
    [
        ("asadnoor.example.pk", "example.pk"),
        ("example.pk", "example.pk"),
        ("www.example.pk", "example.pk"),
        ("deep.nested.example.pk", "example.pk"),
        # Two-label public suffixes must not be mistaken for the domain.
        ("www.ncbaemultan.edu.pk", "ncbaemultan.edu.pk"),
        ("ncbaemultan.edu.pk", "ncbaemultan.edu.pk"),
        ("mail.example.co.uk", "example.co.uk"),
        ("example.com", "example.com"),
        ("sub.example.com", "example.com"),
        ("EXAMPLE.COM.", "example.com"),
    ],
)
def test_registrable_domain(host, expected):
    assert registrable_domain(host) == expected


def test_subdomain_is_detected_as_child_of_its_parent():
    assert registrable_domain("asadnoor.example.pk") != "asadnoor.example.pk"


def test_apex_is_its_own_organizational_domain():
    assert registrable_domain("example.pk") == "example.pk"


# --- Background process helpers --------------------------------------------


def test_read_pid_handles_missing_and_garbage(tmp_path):
    assert daemonlib.read_pid(tmp_path / "absent.pid") is None
    junk = tmp_path / "junk.pid"
    junk.write_text("not-a-pid", encoding="utf-8")
    assert daemonlib.read_pid(junk) is None


def test_write_and_read_pid_round_trip(tmp_path):
    pid_file = tmp_path / "web.pid"
    daemonlib.write_pid_file(pid_file, 4242)
    assert daemonlib.read_pid(pid_file) == 4242


def test_is_running_for_self_and_bogus_pid():
    assert daemonlib.is_running(os.getpid()) is True
    assert daemonlib.is_running(None) is False
    assert daemonlib.is_running(0) is False
    assert daemonlib.is_running(-1) is False


def test_status_clears_a_stale_pid_file(tmp_path):
    pid_file = tmp_path / "stale.pid"
    # PID 999999 is above the usual pid_max and will not exist.
    daemonlib.write_pid_file(pid_file, 999999)
    running, pid = daemonlib.status(pid_file)
    assert running is False
    assert pid == 999999
    assert not pid_file.exists(), "stale PID file should be removed"


def test_status_reports_a_live_process(tmp_path):
    pid_file = tmp_path / "live.pid"
    daemonlib.write_pid_file(pid_file, os.getpid())
    running, pid = daemonlib.status(pid_file)
    assert running is True
    assert pid == os.getpid()


def test_stop_without_pid_file_is_graceful(tmp_path):
    stopped, message = daemonlib.stop(tmp_path / "nothing.pid")
    assert stopped is False
    assert "not running" in message.lower()


def test_stop_terminates_a_real_child_process(tmp_path):
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    pid_file = tmp_path / "child.pid"
    daemonlib.write_pid_file(pid_file, child.pid)
    try:
        stopped, message = daemonlib.stop(pid_file, timeout=10.0)
        assert stopped is True, message
        assert not pid_file.exists()
        deadline = time.monotonic() + 5
        while child.poll() is None and time.monotonic() < deadline:
            time.sleep(0.05)
        assert child.poll() is not None, "child process should be gone"
    finally:
        if child.poll() is None:  # pragma: no cover - safety net
            child.kill()
        child.wait()


def test_runtime_dir_honours_the_env_override(tmp_path, monkeypatch):
    monkeypatch.setenv(daemonlib.DEFAULT_DIR_ENV, str(tmp_path / "rt"))
    assert daemonlib.runtime_dir() == tmp_path / "rt"
    assert (tmp_path / "rt").is_dir()


# --- Launcher wiring --------------------------------------------------------


def test_webserve_exposes_the_background_flags():
    source = (Path(__file__).resolve().parents[1] / "webserve.py").read_text(encoding="utf-8")
    for flag in ('"--background"', '"--stop"', '"--status"', '"--pid-file"', '"--log-file"'):
        assert flag in source, f"webserve.py should define {flag}"


def test_systemd_unit_and_installer_ship():
    root = Path(__file__).resolve().parents[1]
    unit = root / "scripts" / "webosint-web.service"
    installer = root / "scripts" / "install-service.sh"
    assert unit.is_file() and installer.is_file()
    text = unit.read_text(encoding="utf-8")
    assert "WantedBy=multi-user.target" in text, "unit must be enabled at boot"
    # systemd supervises the process itself, so it must not also self-detach.
    exec_lines = [ln for ln in text.splitlines() if ln.startswith("ExecStart=")]
    assert exec_lines, "unit must define ExecStart"
    assert all("--background" not in ln for ln in exec_lines)
    assert installer.read_text(encoding="utf-8").startswith("#!")

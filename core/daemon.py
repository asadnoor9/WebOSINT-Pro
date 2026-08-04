"""
WebOSINT Pro - background process helpers.

Small, dependency-free helpers to run the web UI detached from the terminal
and to manage it afterwards (status / stop). Kept separate from the launcher
so the logic stays unit-testable without importing Flask.
"""

from __future__ import annotations

import errno
import os
import signal
import sys
import time
from pathlib import Path

DEFAULT_DIR_ENV = "WEBOSINT_RUNTIME_DIR"


def runtime_dir() -> Path:
    """Directory holding the PID file and detached log."""
    override = os.environ.get(DEFAULT_DIR_ENV, "").strip()
    base = Path(override) if override else Path.home() / ".webosint"
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    return base


def default_pid_file() -> Path:
    return runtime_dir() / "webosint-web.pid"


def default_log_file() -> Path:
    return runtime_dir() / "webosint-web.log"


def read_pid(pid_file: str | os.PathLike) -> int | None:
    """Return the PID recorded in ``pid_file``, or None if unusable."""
    try:
        raw = Path(pid_file).read_text(encoding="utf-8").strip()
    except (OSError, ValueError):
        return None
    if not raw.isdigit():
        return None
    return int(raw)


def is_running(pid: int | None) -> bool:
    """True if a process with this PID exists and we may signal it."""
    if not pid or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except OSError as exc:
        # EPERM means the process exists but belongs to another user.
        return exc.errno == errno.EPERM
    return True


def write_pid_file(pid_file: str | os.PathLike, pid: int | None = None) -> None:
    path = Path(pid_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(str(pid if pid is not None else os.getpid()), encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass


def remove_pid_file(pid_file: str | os.PathLike) -> None:
    try:
        Path(pid_file).unlink()
    except OSError:
        pass


def status(pid_file: str | os.PathLike) -> tuple[bool, int | None]:
    """Return (running, pid). Clears the PID file when the process is gone."""
    pid = read_pid(pid_file)
    if pid is None:
        return False, None
    if is_running(pid):
        return True, pid
    remove_pid_file(pid_file)
    return False, pid


def stop(pid_file: str | os.PathLike, timeout: float = 10.0) -> tuple[bool, str]:
    """Terminate the recorded process. Returns (stopped, human message)."""
    pid = read_pid(pid_file)
    if pid is None:
        return False, "No PID file found; the background server is not running."
    if not is_running(pid):
        remove_pid_file(pid_file)
        return False, f"No live process for PID {pid}; cleaned up a stale PID file."

    try:
        os.kill(pid, signal.SIGTERM)
    except OSError as exc:
        return False, f"Could not signal PID {pid}: {exc}"

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not is_running(pid):
            remove_pid_file(pid_file)
            return True, f"Stopped background server (PID {pid})."
        time.sleep(0.2)

    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass
    remove_pid_file(pid_file)
    return True, f"Force-killed background server (PID {pid}) after {timeout:.0f}s."


def daemonize(log_file: str | os.PathLike, pid_file: str | os.PathLike) -> None:
    """Detach from the terminal via the standard double fork.

    The working directory is preserved so relative report paths keep working.
    Output is appended to ``log_file``. Only the final child returns.
    """
    if os.name != "posix":  # pragma: no cover - platform guard
        raise RuntimeError(
            "--background requires a POSIX system. On Windows, run the server "
            "as a scheduled task or service instead."
        )

    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    if os.fork() > 0:  # first parent returns to the shell
        os._exit(0)

    os.setsid()

    if os.fork() > 0:  # second parent cannot reacquire a controlling terminal
        os._exit(0)

    os.umask(0o077)
    sys.stdout.flush()
    sys.stderr.flush()

    with open(os.devnull, "rb", 0) as devnull:
        os.dup2(devnull.fileno(), sys.stdin.fileno())
    log_fh = open(log_path, "ab", 0)
    os.dup2(log_fh.fileno(), sys.stdout.fileno())
    os.dup2(log_fh.fileno(), sys.stderr.fileno())

    write_pid_file(pid_file)

    def _cleanup(signum, frame):  # pragma: no cover - signal path
        remove_pid_file(pid_file)
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, _cleanup)
    signal.signal(signal.SIGINT, _cleanup)

"""
Background service supervision, health and status.

Built on the existing ``core.daemon`` primitives (POSIX double-fork, PID file,
stale-PID recovery) and adds the state machine, health checks, runtime metrics
and log rotation the service commands report on.

``psutil`` is optional. When it is missing, memory and CPU are reported as
unavailable rather than blocking the whole status command.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import os
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from core import daemon

LOG = logging.getLogger(__name__)

try:  # pragma: no cover - depends on the host environment
    import psutil

    PSUTIL_AVAILABLE = True
except ImportError:  # pragma: no cover
    PSUTIL_AVAILABLE = False


class ServiceState(str, Enum):
    """Every state the service can report."""

    RUNNING = "running"
    STOPPED = "stopped"
    PAUSED = "paused"
    STARTING = "starting"
    STOPPING = "stopping"
    RESTARTING = "restarting"
    FAILED = "failed"
    CRASHED = "crashed"
    NOT_STARTED = "not_started"
    DISABLED = "disabled"

    @property
    def is_live(self) -> bool:
        return self in (ServiceState.RUNNING, ServiceState.PAUSED, ServiceState.STARTING)


def state_file() -> Path:
    """Where the running process publishes its live metrics."""
    return daemon.runtime_dir() / "service-state.json"


def health_file() -> Path:
    return daemon.runtime_dir() / "health.json"


@dataclass(slots=True)
class RuntimeMetrics:
    """Live counters published by the running process."""

    started_at: float = field(default_factory=time.time)
    last_scan: str = ""
    last_scan_at: float = 0.0
    current_scan: str = ""
    queue_size: int = 0
    running_plugins: list[str] = field(default_factory=list)
    completed_plugins: list[str] = field(default_factory=list)
    current_modules: list[str] = field(default_factory=list)
    scans_completed: int = 0
    scans_failed: int = 0
    paused: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "started_at": self.started_at,
            "last_scan": self.last_scan,
            "last_scan_at": self.last_scan_at,
            "current_scan": self.current_scan,
            "queue_size": self.queue_size,
            "running_plugins": list(self.running_plugins),
            "completed_plugins": list(self.completed_plugins),
            "current_modules": list(self.current_modules),
            "scans_completed": self.scans_completed,
            "scans_failed": self.scans_failed,
            "paused": self.paused,
        }


class MetricsPublisher:
    """Writes runtime metrics to disk so ``status`` can read them out-of-band.

    Uses an atomic replace so a concurrent reader never sees a partial file.
    """

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or state_file()
        self.metrics = RuntimeMetrics()
        self._lock = threading.Lock()

    def update(self, **changes: Any) -> None:
        with self._lock:
            for key, value in changes.items():
                if hasattr(self.metrics, key):
                    setattr(self.metrics, key, value)
            self._flush()

    def plugin_started(self, name: str) -> None:
        with self._lock:
            if name not in self.metrics.running_plugins:
                self.metrics.running_plugins.append(name)
            self._flush()

    def plugin_finished(self, name: str) -> None:
        with self._lock:
            if name in self.metrics.running_plugins:
                self.metrics.running_plugins.remove(name)
            if name not in self.metrics.completed_plugins:
                self.metrics.completed_plugins.append(name)
            self._flush()

    def _flush(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            temporary = self.path.with_suffix(".tmp")
            temporary.write_text(json.dumps(self.metrics.to_dict()), encoding="utf-8")
            temporary.replace(self.path)
        except OSError as exc:  # pragma: no cover - disk issues only
            LOG.debug("Could not publish service metrics: %s", exc)

    def attach(self, bus: Any) -> None:
        """Mirror pipeline events into the published metrics."""
        bus.subscribe("plugin.started", lambda e: self.plugin_started(e.get("plugin", "")))
        bus.subscribe("plugin.finished", lambda e: self.plugin_finished(e.get("plugin", "")))
        bus.subscribe("plugin.failed", lambda e: self.plugin_finished(e.get("plugin", "")))
        bus.subscribe(
            "scan.completed",
            lambda e: self.update(
                last_scan=e.get("target", ""),
                last_scan_at=time.time(),
                current_scan="",
                scans_completed=self.metrics.scans_completed + 1,
            ),
        )
        bus.subscribe("target.normalized", lambda e: self.update(current_scan=e.get("target", "")))


def read_metrics(path: Path | None = None) -> RuntimeMetrics:
    """Read whatever the running process last published."""
    target = path or state_file()
    metrics = RuntimeMetrics()
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return metrics
    for key, value in data.items():
        if hasattr(metrics, key):
            setattr(metrics, key, value)
    return metrics


def process_metrics(pid: int | None) -> dict[str, Any]:
    """Memory, CPU and thread count for the service process."""
    if pid is None:
        return {"available": False, "reason": "The service is not running."}
    if not PSUTIL_AVAILABLE:
        return {
            "available": False,
            "reason": "Install psutil for memory and CPU metrics: pip install psutil",
        }
    try:  # pragma: no cover - requires psutil and a live process
        process = psutil.Process(pid)
        with process.oneshot():
            memory = process.memory_info()
            return {
                "available": True,
                "memory_rss_mb": round(memory.rss / (1024 * 1024), 1),
                "memory_percent": round(process.memory_percent(), 2),
                "cpu_percent": round(process.cpu_percent(interval=0.1), 1),
                "threads": process.num_threads(),
                "open_files": len(process.open_files()),
                "create_time": process.create_time(),
            }
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "reason": f"{type(exc).__name__}: {exc}"}


@dataclass(slots=True)
class ServiceStatus:
    """The complete answer to ``webosint status``."""

    state: ServiceState
    pid: int | None = None
    uptime_seconds: float = 0.0
    pid_file: str = ""
    log_file: str = ""
    metrics: RuntimeMetrics = field(default_factory=RuntimeMetrics)
    process: dict[str, Any] = field(default_factory=dict)
    boot_enabled: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "pid": self.pid,
            "uptime_seconds": round(self.uptime_seconds, 1),
            "uptime_human": humanize_duration(self.uptime_seconds),
            "pid_file": self.pid_file,
            "log_file": self.log_file,
            "boot_enabled": self.boot_enabled,
            "process": self.process,
            **self.metrics.to_dict(),
        }


def humanize_duration(seconds: float) -> str:
    if seconds <= 0:
        return "-"
    seconds = int(seconds)
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    if days:
        return f"{days}d {hours}h {minutes}m"
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m {seconds}s"
    return f"{seconds}s"


def boot_enabled() -> bool:
    """Whether a boot-time unit is installed for the current platform."""
    candidates = [
        Path("/etc/systemd/system/webosint.service"),
        Path("/etc/systemd/system/webosint-web.service"),
        Path("/Library/LaunchDaemons/pk.webosint.plist"),
        Path.home() / ".config/systemd/user/webosint.service",
    ]
    return any(path.exists() for path in candidates)


SYSTEMD_UNIT = "webosint"


def systemd_state(unit: str = SYSTEMD_UNIT) -> dict[str, Any]:
    """Ask systemd about the unit, if systemd is managing us at all.

    Under systemd the process runs in the foreground and writes no PID file, so
    a PID-file-only check reports "not started" for a perfectly healthy service.
    Returns an empty dict when systemd is unavailable or does not know the unit.
    """
    systemctl = shutil.which("systemctl")
    if not systemctl:
        return {}
    try:
        completed = subprocess.run(  # noqa: S603
            [
                systemctl,
                "show",
                f"{unit}.service",
                "--property=LoadState,ActiveState,SubState,MainPID,ExecMainStartTimestamp",
            ],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return {}

    values: dict[str, str] = {}
    for line in completed.stdout.splitlines():
        key, _, value = line.partition("=")
        if key:
            values[key] = value

    if values.get("LoadState") not in {"loaded"}:
        return {}

    try:
        main_pid = int(values.get("MainPID", "0"))
    except ValueError:
        main_pid = 0

    return {
        "managed": True,
        "active_state": values.get("ActiveState", ""),
        "sub_state": values.get("SubState", ""),
        "pid": main_pid or None,
        "started_at": values.get("ExecMainStartTimestamp", ""),
    }


_SYSTEMD_STATES = {
    "active": ServiceState.RUNNING,
    "activating": ServiceState.STARTING,
    "deactivating": ServiceState.STOPPING,
    "reloading": ServiceState.RESTARTING,
    "failed": ServiceState.FAILED,
    "inactive": ServiceState.STOPPED,
}


def current_status(pid_file: Path | None = None) -> ServiceStatus:
    """Determine the service state without touching the process."""
    resolved_pid_file = Path(pid_file) if pid_file else daemon.default_pid_file()
    running, pid = daemon.status(resolved_pid_file)
    metrics = read_metrics()

    unit = systemd_state()

    if running:
        state = ServiceState.PAUSED if metrics.paused else ServiceState.RUNNING
    elif unit.get("managed"):
        # systemd runs the process in the foreground, so there is no PID file to
        # find. Trust systemd over the absent file.
        state = _SYSTEMD_STATES.get(unit.get("active_state", ""), ServiceState.NOT_STARTED)
        if unit.get("sub_state") == "auto-restart":
            state = ServiceState.CRASHED
        if state is ServiceState.RUNNING:
            pid = unit.get("pid") or pid
            running = True
            if metrics.paused:
                state = ServiceState.PAUSED
    elif resolved_pid_file.exists():
        # A PID file that outlived its process means the last exit was unclean.
        state = ServiceState.CRASHED
    elif metrics.started_at and metrics.scans_completed:
        state = ServiceState.STOPPED
    else:
        state = ServiceState.NOT_STARTED

    uptime = 0.0
    if running and metrics.started_at:
        uptime = max(0.0, time.time() - float(metrics.started_at))

    return ServiceStatus(
        state=state,
        pid=pid,
        uptime_seconds=uptime,
        pid_file=str(resolved_pid_file),
        log_file=str(daemon.default_log_file()),
        metrics=metrics,
        process=process_metrics(pid if running else None),
        boot_enabled=boot_enabled(),
    )


def health_check(pid_file: Path | None = None) -> dict[str, Any]:
    """Structured health report suitable for a monitoring probe.

    Exit-code semantics: ``healthy`` -> 0, ``degraded`` -> 1, ``unhealthy`` -> 2.
    """
    status = current_status(pid_file)
    checks: list[dict[str, Any]] = []

    def add(name: str, ok: bool, detail: str) -> None:
        checks.append({"check": name, "ok": ok, "detail": detail})

    add(
        "process",
        status.state.is_live,
        f"Service state is {status.state.value}" + (f" (pid {status.pid})" if status.pid else ""),
    )

    runtime = daemon.runtime_dir()
    add(
        "runtime_directory",
        os.access(runtime, os.W_OK),
        f"{runtime} is writable" if os.access(runtime, os.W_OK) else f"{runtime} is not writable",
    )

    log_path = Path(status.log_file)
    stale = False
    if log_path.exists():
        age = time.time() - log_path.stat().st_mtime
        stale = status.state.is_live and age > 3600
        add(
            "log_freshness",
            not stale,
            f"Last log write {humanize_duration(age)} ago",
        )
    else:
        add("log_freshness", not status.state.is_live, "No log file yet")

    try:
        from engine.storage import Storage

        store = Storage()
        add(
            "database",
            store.available,
            f"Connected to {store.url}" if store.available else "Falling back to in-memory history",
        )
        store.close()
    except Exception as exc:  # noqa: BLE001
        add("database", False, f"{type(exc).__name__}: {exc}")

    failed = [check for check in checks if not check["ok"]]
    if not failed:
        overall = "healthy"
    elif status.state.is_live:
        overall = "degraded"
    else:
        overall = "unhealthy"

    report = {
        "status": overall,
        "state": status.state.value,
        "pid": status.pid,
        "uptime": humanize_duration(status.uptime_seconds),
        "checks": checks,
        "checked_at": time.time(),
    }
    try:
        health_file().write_text(json.dumps(report, indent=2), encoding="utf-8")
    except OSError:  # pragma: no cover
        pass
    return report


def configure_rotating_logs(
    log_file: Path | None = None,
    *,
    max_bytes: int = 10 * 1024 * 1024,
    backups: int = 5,
    json_format: bool = True,
    level: int = logging.INFO,
) -> logging.Handler:
    """Install a size-based rotating handler on the root logger."""
    path = Path(log_file) if log_file else daemon.default_log_file()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    handler = logging.handlers.RotatingFileHandler(
        path, maxBytes=max_bytes, backupCount=backups, encoding="utf-8"
    )
    handler.setLevel(level)
    handler.setFormatter(
        JsonFormatter()
        if json_format
        else logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    )

    root = logging.getLogger()
    root.setLevel(level)
    root.addHandler(handler)
    return handler


class JsonFormatter(logging.Formatter):
    """One JSON object per line, suitable for shipping to a SIEM."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        for key, value in getattr(record, "__dict__", {}).items():
            if key.startswith("webosint_"):
                payload[key[9:]] = value
        return json.dumps(payload, default=str)


def tail_log(lines: int = 50, log_file: Path | None = None) -> list[str]:
    """Return the last ``lines`` lines of the service log."""
    path = Path(log_file) if log_file else daemon.default_log_file()
    if not path.exists():
        return []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            return [line.rstrip("\n") for line in handle.readlines()[-lines:]]
    except OSError as exc:  # pragma: no cover
        return [f"Could not read {path}: {exc}"]

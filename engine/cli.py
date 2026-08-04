"""
Service management command line.

Implements the ``webosint <command>`` surface. Every command returns a POSIX
exit code so it can be used from monitoring, CI and systemd health checks:

    0  success / healthy
    1  degraded or command-specific failure
    2  unhealthy or not running
    3  usage error
"""

from __future__ import annotations

import argparse
import json
import os
import platform as platform_module
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from core import daemon
from engine import __version__
from engine.service import (
    ServiceState,
    current_status,
    health_check,
    humanize_duration,
    tail_log,
)

REPO_ROOT = Path(__file__).resolve().parent.parent

# ANSI colours, disabled when not writing to a terminal or when NO_COLOR is set.
_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def _paint(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _COLOR else text


def bold(text: str) -> str:
    return _paint(text, "1")


def green(text: str) -> str:
    return _paint(text, "32")


def yellow(text: str) -> str:
    return _paint(text, "33")


def red(text: str) -> str:
    return _paint(text, "31")


def dim(text: str) -> str:
    return _paint(text, "2")


STATE_COLOURS = {
    ServiceState.RUNNING: green,
    ServiceState.PAUSED: yellow,
    ServiceState.STARTING: yellow,
    ServiceState.STOPPING: yellow,
    ServiceState.RESTARTING: yellow,
    ServiceState.STOPPED: dim,
    ServiceState.NOT_STARTED: dim,
    ServiceState.DISABLED: dim,
    ServiceState.FAILED: red,
    ServiceState.CRASHED: red,
}


def _row(label: str, value: Any) -> str:
    return f"  {label:<20} {value}"


# --- commands ---------------------------------------------------------------


def cmd_start(args: argparse.Namespace) -> int:
    """Start the web service in the background (single instance only)."""
    status = current_status()
    if status.state.is_live:
        print(yellow(f"WebOSINT is already running (pid {status.pid})."))
        return 1

    script = REPO_ROOT / "webserve.py"
    if not script.exists():
        print(red(f"Cannot find {script}."))
        return 1

    argv = [sys.executable, str(script), "--background"]
    if args.host:
        argv += ["--host", args.host]
    if args.port:
        argv += ["--port", str(args.port)]

    print(f"Starting WebOSINT on {args.host}:{args.port} ...")
    completed = subprocess.run(argv, cwd=str(REPO_ROOT), check=False)
    if completed.returncode != 0:
        print(red("The service failed to start. Check the log with: webosint logs"))
        return 1

    # Give the child a moment to write its PID file before we confirm.
    for _ in range(20):
        time.sleep(0.25)
        if current_status().state.is_live:
            break

    status = current_status()
    if status.state.is_live:
        print(green(f"Started (pid {status.pid})."))
        return 0
    print(red("The service did not come up. Check the log with: webosint logs"))
    return 1


def cmd_stop(args: argparse.Namespace) -> int:
    """Stop the service gracefully (SIGTERM, then SIGKILL if needed)."""
    stopped, message = daemon.stop(daemon.default_pid_file(), timeout=args.timeout)
    print(green(message) if stopped else yellow(message))
    return 0 if stopped else 1


def cmd_restart(args: argparse.Namespace) -> int:
    """Stop then start, preserving the listening address."""
    cmd_stop(args)
    time.sleep(1.0)
    return cmd_start(args)


def cmd_reload(args: argparse.Namespace) -> int:
    """Reload configuration and plugins without dropping the process.

    Sends SIGHUP, which the service handles by re-reading config and
    re-registering plugins. Falls back to a restart where SIGHUP is unavailable.
    """
    status = current_status()
    if not status.state.is_live or status.pid is None:
        print(yellow("The service is not running; nothing to reload."))
        return 1

    if not hasattr(signal, "SIGHUP"):
        print(yellow("SIGHUP is unavailable on this platform; restarting instead."))
        return cmd_restart(args)

    try:
        os.kill(status.pid, signal.SIGHUP)
    except OSError as exc:
        print(red(f"Could not signal pid {status.pid}: {exc}"))
        return 1
    print(green(f"Reload signal sent to pid {status.pid}."))
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    """Print the full service status."""
    status = current_status()
    payload = status.to_dict()

    if args.json:
        print(json.dumps(payload, indent=2, default=str))
        return 0 if status.state.is_live else 2

    colour = STATE_COLOURS.get(status.state, dim)
    print(bold("WebOSINT Pro service"))
    print(_row("State", colour(status.state.value.replace("_", " ").title())))
    print(_row("PID", status.pid if status.pid else "-"))
    print(_row("Uptime", humanize_duration(status.uptime_seconds)))

    process = status.process
    if process.get("available"):
        print(_row("Memory", f"{process['memory_rss_mb']} MB ({process['memory_percent']}%)"))
        print(_row("CPU", f"{process['cpu_percent']}%"))
        print(_row("Threads", process["threads"]))
    else:
        print(_row("Memory / CPU", dim(process.get("reason", "unavailable"))))

    metrics = status.metrics
    print(_row("Queue size", metrics.queue_size))
    print(_row("Current scan", metrics.current_scan or "-"))
    print(_row("Last scan", metrics.last_scan or "-"))
    print(_row("Scans completed", metrics.scans_completed))
    print(_row("Running plugins", ", ".join(metrics.running_plugins) or "-"))
    print(
        _row(
            "Completed plugins",
            f"{len(metrics.completed_plugins)} ({', '.join(metrics.completed_plugins[:6])})"
            if metrics.completed_plugins
            else "-",
        )
    )
    print(_row("Current modules", ", ".join(metrics.current_modules) or "-"))
    print(_row("Start on boot", green("enabled") if status.boot_enabled else dim("not enabled")))
    print(_row("PID file", dim(status.pid_file)))
    print(_row("Log file", dim(status.log_file)))
    return 0 if status.state.is_live else 2


def cmd_health(args: argparse.Namespace) -> int:
    """Run health checks and report an exit code a monitor can consume."""
    report = health_check()
    if args.json:
        print(json.dumps(report, indent=2, default=str))
    else:
        overall = report["status"]
        colour = {"healthy": green, "degraded": yellow}.get(overall, red)
        print(bold("Health: ") + colour(overall.upper()))
        for check in report["checks"]:
            mark = green("PASS") if check["ok"] else red("FAIL")
            print(f"  [{mark}] {check['check']}: {check['detail']}")
    return {"healthy": 0, "degraded": 1}.get(report["status"], 2)


def cmd_logs(args: argparse.Namespace) -> int:
    """Show, or follow, the service log."""
    path = daemon.default_log_file()
    if not path.exists():
        print(dim(f"No log file yet at {path}."))
        return 1

    for line in tail_log(args.lines):
        print(line)

    if not args.follow:
        return 0

    print(dim("-- following, press Ctrl-C to stop --"))
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            handle.seek(0, os.SEEK_END)
            while True:
                line = handle.readline()
                if line:
                    print(line.rstrip("\n"))
                else:
                    time.sleep(0.4)
    except KeyboardInterrupt:
        return 0


def cmd_version(args: argparse.Namespace) -> int:
    """Print version and environment information."""
    info = {
        "engine_version": __version__,
        "python": platform_module.python_version(),
        "platform": platform_module.platform(),
        "repository": str(REPO_ROOT),
    }
    if args.json:
        print(json.dumps(info, indent=2))
        return 0
    print(bold(f"WebOSINT Pro {__version__}"))
    for key, value in info.items():
        if key != "engine_version":
            print(_row(key.replace("_", " ").title(), value))
    return 0


def cmd_update(args: argparse.Namespace) -> int:
    """Update the working copy from git and reinstall dependencies.

    Refuses to run when the working tree is dirty, so local changes are never
    silently discarded.
    """
    git = shutil.which("git")
    if git is None:
        print(red("git is not installed, so this checkout cannot be updated automatically."))
        return 1
    if not (REPO_ROOT / ".git").exists():
        print(yellow("This is not a git checkout; update it the way you installed it."))
        return 1

    dirty = subprocess.run(
        [git, "status", "--porcelain"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    if dirty.stdout.strip() and not args.force:
        print(red("The working tree has uncommitted changes. Commit or stash them first,"))
        print(red("or re-run with --force if you are certain."))
        return 1

    print("Fetching updates ...")
    pull = subprocess.run([git, "pull", "--ff-only"], cwd=str(REPO_ROOT), check=False)
    if pull.returncode != 0:
        print(red("git pull failed; resolve the conflict manually."))
        return 1

    print("Reinstalling dependencies ...")
    subprocess.run(
        [sys.executable, "-m", "pip", "install", "-e", "."], cwd=str(REPO_ROOT), check=False
    )
    print(green("Update complete. Restart the service with: webosint restart"))
    return 0


def _check(name: str, ok: bool, detail: str, advice: str = "") -> dict[str, Any]:
    return {"name": name, "ok": ok, "detail": detail, "advice": advice}


def cmd_doctor(args: argparse.Namespace) -> int:
    """Diagnose the installation and tell the operator exactly what to fix."""
    checks: list[dict[str, Any]] = []

    version = sys.version_info
    python_ok = version >= (3, 10)
    checks.append(
        _check(
            "Python version",
            python_ok,
            f"{platform_module.python_version()}",
            "" if python_ok else "WebOSINT Pro requires Python 3.10 or newer.",
        )
    )

    # Optional dependencies, grouped by the capability they unlock.
    optional = {
        "dns": ("DNS, mail and subdomain checks", "pip install dnspython"),
        "requests": ("all HTTP checks", "pip install requests"),
        "flask": ("the web dashboard", "pip install '.[web]'"),
        "sqlalchemy": ("scan history and the target inventory", "pip install sqlalchemy"),
        "docx": ("Word reports", "pip install '.[reports]'"),
        "reportlab": ("PDF reports", "pip install '.[reports]'"),
        "openpyxl": ("Excel reports", "pip install openpyxl"),
        "whois": ("WHOIS lookups", "pip install python-whois"),
        "psutil": ("memory and CPU metrics in status", "pip install psutil"),
        "jinja2": ("HTML report templating", "pip install jinja2"),
    }
    import importlib.util

    for module, (capability, advice) in optional.items():
        present = importlib.util.find_spec(module) is not None
        checks.append(
            _check(
                f"Package: {module}",
                present,
                f"{'available' if present else 'missing'} - powers {capability}",
                "" if present else advice,
            )
        )

    # External tools.
    for tool, advice in (("nmap", "apt install nmap"), ("git", "apt install git")):
        found = shutil.which(tool)
        checks.append(
            _check(
                f"Tool: {tool}",
                found is not None,
                found or "not on PATH",
                "" if found else advice,
            )
        )

    # Runtime directory.
    runtime = daemon.runtime_dir()
    writable = os.access(runtime, os.W_OK)
    checks.append(
        _check(
            "Runtime directory",
            writable,
            f"{runtime} ({'writable' if writable else 'not writable'})",
            "" if writable else f"chmod u+w {runtime}",
        )
    )

    # Service state.
    status = current_status()
    checks.append(
        _check(
            "Service",
            status.state is not ServiceState.CRASHED,
            status.state.value,
            "A stale PID file suggests an unclean exit; run: webosint start"
            if status.state is ServiceState.CRASHED
            else "",
        )
    )
    checks.append(
        _check(
            "Start on boot",
            status.boot_enabled,
            "enabled" if status.boot_enabled else "not enabled",
            "" if status.boot_enabled else "sudo ./scripts/install-service.sh",
        )
    )

    blocking_names = {"Python version", "Runtime directory"}
    blocking = [c for c in checks if not c["ok"] and c["name"] in blocking_names]
    warnings = [c for c in checks if not c["ok"] and c["name"] not in blocking_names]

    if args.json:
        print(
            json.dumps(
                {
                    "checks": checks,
                    "blocking": [c["name"] for c in blocking],
                    "warnings": [c["name"] for c in warnings],
                    "status": "unusable" if blocking else ("degraded" if warnings else "healthy"),
                },
                indent=2,
            )
        )
    else:
        print(bold("WebOSINT Pro doctor"))
        for check in checks:
            mark = green("ok  ") if check["ok"] else yellow("warn")
            print(f"  [{mark}] {check['name']}: {check['detail']}")
            if check["advice"]:
                print(dim(f"         fix: {check['advice']}"))

        print()
        if blocking:
            print(red("Installation is not usable until the blocking item above is resolved."))
        elif warnings:
            print(yellow(f"{len(warnings)} optional capability/capabilities are unavailable."))
        else:
            print(green("Everything checks out."))

    # Optional capabilities that are merely absent are not a failure: exiting
    # non-zero for them would make doctor unusable in a healthcheck or CI gate.
    return 1 if blocking else 0


# --- parser -----------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webosint",
        description="WebOSINT Pro service management.",
    )
    parser.add_argument("--version", action="version", version=f"WebOSINT Pro {__version__}")
    subparsers = parser.add_subparsers(dest="command", metavar="<command>")

    def add(name: str, handler: Any, help_text: str) -> argparse.ArgumentParser:
        sub = subparsers.add_parser(name, help=help_text, description=handler.__doc__)
        sub.set_defaults(handler=handler)
        sub.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
        return sub

    for name, handler, help_text in (
        ("start", cmd_start, "Start the service in the background."),
        ("restart", cmd_restart, "Restart the service."),
    ):
        sub = add(name, handler, help_text)
        sub.add_argument("--host", default="127.0.0.1", help="Listen address.")
        sub.add_argument("--port", type=int, default=8000, help="Listen port.")
        sub.add_argument("--timeout", type=float, default=10.0, help="Shutdown grace period.")

    stop = add("stop", cmd_stop, "Stop the service gracefully.")
    stop.add_argument("--timeout", type=float, default=10.0, help="Shutdown grace period.")

    reload_cmd = add("reload", cmd_reload, "Reload configuration and plugins in place.")
    reload_cmd.add_argument("--host", default="127.0.0.1", help=argparse.SUPPRESS)
    reload_cmd.add_argument("--port", type=int, default=8000, help=argparse.SUPPRESS)
    reload_cmd.add_argument("--timeout", type=float, default=10.0, help=argparse.SUPPRESS)

    add("status", cmd_status, "Show the full service status.")
    add("health", cmd_health, "Run health checks.")

    logs = add("logs", cmd_logs, "Show the service log.")
    logs.add_argument("-n", "--lines", type=int, default=50, help="How many lines to show.")
    logs.add_argument("-f", "--follow", action="store_true", help="Follow the log.")

    add("version", cmd_version, "Show version and environment information.")

    update = add("update", cmd_update, "Update this checkout and its dependencies.")
    update.add_argument("--force", action="store_true", help="Update despite local changes.")

    add("doctor", cmd_doctor, "Diagnose the installation.")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "handler", None):
        parser.print_help()
        return 3
    try:
        return int(args.handler(args))
    except KeyboardInterrupt:
        print()
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

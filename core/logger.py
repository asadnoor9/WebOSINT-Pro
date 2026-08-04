"""
WebOSINT Pro - Structured logger

  * Every record passes through the redactor before it reaches a console or a
    file, so API keys, cookies, internal IPs and local paths never get logged.
  * Console levels: quiet / default / verbose (-v) / debug (-vv).
  * File logs are JSON lines (one object per record) and are optional.
  * Repeated identical console messages are suppressed to keep output low-noise.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import os
import sys
from datetime import datetime, timezone
from typing import Any

from core.redaction import DEFAULT_REDACTOR, Redactor

TRACE = 5
logging.addLevelName(TRACE, "TRACE")


def _ansi(code: str) -> str:
    return code if sys.stderr.isatty() else ""


RESET = _ansi("\033[0m")
BOLD = _ansi("\033[1m")
DIM = _ansi("\033[2m")
RED = _ansi("\033[91m")
GREEN = _ansi("\033[92m")
YELLOW = _ansi("\033[93m")
CYAN = _ansi("\033[96m")
MAGENTA = _ansi("\033[95m")


# ── Redaction filter ─────────────────────────────────────────────────────────


class RedactionFilter(logging.Filter):
    """Scrubs sensitive values from every log record, whatever the handler."""

    def __init__(self, redactor: Redactor | None = None) -> None:
        super().__init__()
        self.redactor = redactor or DEFAULT_REDACTOR

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            record.msg = self.redactor.text(record.getMessage())
            record.args = ()
        except Exception:
            record.msg = "[unloggable message redacted]"
            record.args = ()
        for attr in ("url", "finding_value", "target"):
            value = getattr(record, attr, None)
            if isinstance(value, str):
                setattr(record, attr, self.redactor.text(value))
        # Stack traces are never written out; they can contain paths and payloads.
        record.exc_info = None
        record.exc_text = None
        return True


class DedupeFilter(logging.Filter):
    """Drops an identical consecutive message so the console stays readable."""

    def __init__(self, window: int = 25) -> None:
        super().__init__()
        self._seen: list[str] = []
        self._window = window

    def filter(self, record: logging.LogRecord) -> bool:
        key = f"{record.levelno}:{record.getMessage()}"
        if key in self._seen:
            return False
        self._seen.append(key)
        if len(self._seen) > self._window:
            self._seen.pop(0)
        return True


# ── Formatters ──────────────────────────────────────────────────────────────


class JSONFormatter(logging.Formatter):
    """One JSON object per line, safe for SIEM ingestion."""

    def __init__(self, session_id: str = "") -> None:
        super().__init__()
        self.session_id = session_id

    def format(self, record: logging.LogRecord) -> str:
        doc: dict[str, Any] = {
            "@timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
            "session_id": self.session_id,
        }
        for attr in (
            "module_name",
            "url",
            "status_code",
            "elapsed_ms",
            "risk",
            "finding_key",
            "audit_event",
        ):
            value = getattr(record, attr, None)
            if value is not None:
                doc[attr] = value
        return json.dumps(doc, ensure_ascii=False, sort_keys=True)


class ConsoleFormatter(logging.Formatter):
    _STYLES = {
        "TRACE": DIM,
        "DEBUG": DIM,
        "INFO": CYAN,
        "WARNING": YELLOW,
        "ERROR": RED,
        "CRITICAL": RED + BOLD,
    }
    _ICONS = {
        "TRACE": ".",
        "DEBUG": ".",
        "INFO": ">",
        "WARNING": "!",
        "ERROR": "x",
        "CRITICAL": "x",
    }

    def format(self, record: logging.LogRecord) -> str:
        color = self._STYLES.get(record.levelname, RESET)
        icon = self._ICONS.get(record.levelname, ">")
        stamp = datetime.fromtimestamp(record.created).strftime("%H:%M:%S")
        return f"{DIM}{stamp}{RESET} {color}{icon}{RESET} {record.getMessage()}"


# ── Logger ──────────────────────────────────────────────────────────────────


class WebOSINTLogger(logging.Logger):
    """Logger with scan-specific helpers."""

    def trace(self, msg: str, *args: Any, **kwargs: Any) -> None:
        if self.isEnabledFor(TRACE):
            self._log(TRACE, msg, args, **kwargs)

    def request(
        self,
        method: str,
        url: str,
        status: int | None = None,
        elapsed_ms: float | None = None,
    ) -> None:
        """HTTP request line — debug only (-vv)."""
        if not self.isEnabledFor(logging.DEBUG):
            return
        status_text = f" {status}" if status is not None else " -"
        timing = f" {elapsed_ms:.0f}ms" if elapsed_ms is not None else ""
        self.debug(
            f"{method} {url}{status_text}{timing}",
            extra={"url": url, "status_code": status, "elapsed_ms": elapsed_ms},
        )

    def finding(self, module: str, key: str, value: Any, risk: str = "info") -> None:
        """Notable finding — shown at -v."""
        if not self.isEnabledFor(logging.INFO):
            return
        colors = {
            "critical": RED + BOLD,
            "high": RED,
            "medium": YELLOW,
            "low": CYAN,
            "info": DIM,
        }
        color = colors.get(str(risk).lower(), RESET)
        text = str(value)[:120]
        self.info(
            f"[{module}] {color}{key}{RESET}: {text}",
            extra={"module_name": module, "finding_key": key, "risk": risk},
        )

    def module_start(self, name: str) -> None:
        if self.isEnabledFor(logging.INFO):
            self.info(f"{name} started", extra={"module_name": name})

    def module_done(self, name: str, count: int, elapsed_ms: float) -> None:
        if self.isEnabledFor(logging.INFO):
            self.info(
                f"{name} done | {count} findings | {elapsed_ms:.0f}ms",
                extra={"module_name": name, "elapsed_ms": elapsed_ms},
            )

    def raw(self, label: str, data: Any) -> None:
        """Raw payload dump — only at TRACE and only when raw capture is enabled."""
        if self.isEnabledFor(TRACE):
            self.trace(f"[raw {label}] {str(data)[:400]}")

    def audit(self, event: str, **kwargs: Any) -> None:
        self.info(f"[audit] {event}", extra={"audit_event": event, **kwargs})


logging.setLoggerClass(WebOSINTLogger)


def console_level(verbose: int = 0, quiet: bool = False) -> int:
    if quiet:
        return logging.ERROR
    return {0: logging.WARNING, 1: logging.INFO}.get(verbose, logging.DEBUG)


def setup_logger(
    verbose: int = 0,
    quiet: bool = False,
    log_dir: str = "logs",
    session_id: str = "",
    redactor: Redactor | None = None,
    write_files: bool = True,
) -> WebOSINTLogger:
    """Build the singleton scan logger.

    Console: quiet (errors) / default (warnings) / -v (info) / -vv (debug)
    Files:   optional JSON lines, rotating, redacted, 0600 permissions
    """
    log: WebOSINTLogger = logging.getLogger("webosint")  # type: ignore[assignment]
    log.setLevel(TRACE)
    log.handlers.clear()
    log.filters.clear()
    log.propagate = False

    redaction = RedactionFilter(redactor)
    log.addFilter(redaction)

    console = logging.StreamHandler(sys.stderr)
    console.setLevel(console_level(verbose, quiet))
    console.setFormatter(ConsoleFormatter())
    console.addFilter(redaction)
    console.addFilter(DedupeFilter())
    log.addHandler(console)

    if write_files:
        os.makedirs(log_dir, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = os.path.join(log_dir, f"webosint_{session_id or stamp}.jsonl")
        handler = logging.handlers.RotatingFileHandler(
            json_path, maxBytes=5 * 1024 * 1024, backupCount=2, encoding="utf-8"
        )
        handler.setLevel(logging.DEBUG if verbose >= 2 else logging.INFO)
        handler.setFormatter(JSONFormatter(session_id=session_id or stamp))
        handler.addFilter(redaction)
        log.addHandler(handler)
        try:
            os.chmod(json_path, 0o600)
        except OSError:
            pass

    return log

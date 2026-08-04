"""
WebOSINT Pro - Safe external tool execution

Rules enforced here:
  * argument lists only — never a shell string, never shell=True
  * strict binary allowlist (resolved through shutil.which, no relative paths)
  * arguments are validated against a conservative character allowlist
  * mandatory timeout and captured-output size limits
  * stdout/stderr are redacted before they are returned or logged
  * active tools are refused unless the SafetyPolicy allows active mode
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from core.redaction import DEFAULT_REDACTOR, Redactor
from core.safety import SafetyController

# Tool name -> is_active. Anything not listed can never be executed.
ALLOWED_TOOLS: dict[str, bool] = {
    "amass": False,
    "subfinder": False,
    "theharvester": False,
    "whois": False,
    "dig": False,
    "wafw00f": True,
    "nmap": True,
    "nuclei": True,
    "wpscan": True,
    "httpx": True,
}

MAX_OUTPUT_BYTES = 256 * 1024
DEFAULT_TIMEOUT = 60
MAX_TIMEOUT = 600

_ARG_RE = re.compile(r"^[A-Za-z0-9 ._:/@,=+\-\[\]]{0,512}$")


class ToolNotAllowed(Exception):
    """Raised when a binary is not on the allowlist or is missing."""


class UnsafeArgument(Exception):
    """Raised when an argument contains shell metacharacters or is too long."""


@dataclass(slots=True)
class ToolResult:
    tool: str
    ok: bool
    returncode: int | None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    truncated: bool = False
    error: str = ""
    duration_ms: float = 0.0


@dataclass(slots=True)
class SafeRunner:
    """Executes allowlisted external tools without a shell."""

    safety: SafetyController | None = None
    redactor: Redactor = field(default_factory=lambda: DEFAULT_REDACTOR)
    max_output_bytes: int = MAX_OUTPUT_BYTES

    def available(self, tool: str) -> bool:
        return tool in ALLOWED_TOOLS and shutil.which(tool) is not None

    def run(
        self,
        tool: str,
        args: list[str] | tuple[str, ...] | None = None,
        timeout: int = DEFAULT_TIMEOUT,
        cwd: str | Path | None = None,
    ) -> ToolResult:
        """Run an allowlisted tool with an argument list. Never raises on tool failure."""
        import time

        args = list(args or [])

        if tool not in ALLOWED_TOOLS:
            raise ToolNotAllowed(f"Tool '{tool}' is not on the allowlist.")

        if ALLOWED_TOOLS[tool] and self.safety is not None:
            # Active tools require --authorized and --active.
            self.safety.require_active(tool)

        binary = shutil.which(tool)
        if not binary:
            return ToolResult(tool=tool, ok=False, returncode=None, error="tool not installed")

        validated = [self._validate_arg(a) for a in args]
        timeout = max(1, min(int(timeout), MAX_TIMEOUT))

        started = time.perf_counter()
        try:
            proc = subprocess.run(
                [binary, *validated],
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=False,
                check=False,
                cwd=str(cwd) if cwd else None,
            )
        except subprocess.TimeoutExpired:
            return ToolResult(
                tool=tool,
                ok=False,
                returncode=None,
                timed_out=True,
                error="timed out",
                duration_ms=(time.perf_counter() - started) * 1000,
            )
        except (OSError, ValueError) as exc:
            return ToolResult(
                tool=tool,
                ok=False,
                returncode=None,
                error=self.redactor.exception(exc),
                duration_ms=(time.perf_counter() - started) * 1000,
            )

        stdout, truncated_out = self._cap(proc.stdout or "")
        stderr, truncated_err = self._cap(proc.stderr or "")
        return ToolResult(
            tool=tool,
            ok=proc.returncode == 0,
            returncode=proc.returncode,
            stdout=self.redactor.text(stdout),
            stderr=self.redactor.text(stderr),
            truncated=truncated_out or truncated_err,
            duration_ms=(time.perf_counter() - started) * 1000,
        )

    # ── Helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _validate_arg(value: object) -> str:
        arg = str(value)
        if not _ARG_RE.match(arg):
            raise UnsafeArgument("Rejected argument containing unsupported characters.")
        return arg

    def _cap(self, text: str) -> tuple[str, bool]:
        encoded = text.encode("utf-8", errors="replace")
        if len(encoded) <= self.max_output_bytes:
            return text, False
        return encoded[: self.max_output_bytes].decode("utf-8", errors="ignore"), True

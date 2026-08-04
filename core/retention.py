"""
WebOSINT Pro - Output retention & temp file cleanup

Generated artifacts (reports, logs, temp files) are scan data and should not
linger forever on disk. This module implements a simple, predictable retention
policy that runs at the end of every scan.
"""

from __future__ import annotations

import os
import tempfile
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

# Only files matching these suffixes are ever removed by the cleaner.
MANAGED_SUFFIXES = (".json", ".html", ".md", ".log", ".jsonl", ".tmp", ".csv")
TEMP_PREFIX = "webosint_"


@dataclass(slots=True)
class RetentionPolicy:
    """How long generated artifacts are kept, in days. 0 disables cleanup."""

    reports_days: int = 30
    logs_days: int = 14
    temp_files: bool = True
    enabled: bool = True
    _temp_paths: list[str] = field(default_factory=list)

    # ── Temp file tracking ────────────────────────────────────────────────────

    def temp_file(self, suffix: str = ".tmp") -> str:
        """Create a tracked temp file that is deleted during cleanup."""
        fd, path = tempfile.mkstemp(suffix=suffix, prefix=TEMP_PREFIX)
        os.close(fd)
        os.chmod(path, 0o600)
        self._temp_paths.append(path)
        return path

    def track(self, path: str | Path) -> None:
        self._temp_paths.append(str(path))

    # ── Cleanup ───────────────────────────────────────────────────────────────

    def cleanup_temp(self) -> int:
        removed = 0
        if not self.temp_files:
            return 0
        for path in list(self._temp_paths):
            try:
                Path(path).unlink(missing_ok=True)
                removed += 1
            except OSError:
                continue
            finally:
                self._temp_paths.remove(path)
        return removed

    def cleanup_dir(self, directory: str | Path, max_age_days: int) -> int:
        """Delete managed artifacts older than ``max_age_days`` in a directory."""
        if not self.enabled or max_age_days <= 0:
            return 0
        base = Path(directory)
        if not base.is_dir():
            return 0

        cutoff = time.time() - (max_age_days * 86400)
        removed = 0
        for entry in self._iter_managed(base):
            try:
                if entry.stat().st_mtime < cutoff:
                    entry.unlink()
                    removed += 1
            except OSError:
                continue
        return removed

    def run(self, output_dir: str | Path, log_dir: str | Path) -> dict[str, int]:
        """Run the full retention pass. Returns a count summary."""
        return {
            "temp_removed": self.cleanup_temp(),
            "reports_removed": self.cleanup_dir(output_dir, self.reports_days),
            "logs_removed": self.cleanup_dir(log_dir, self.logs_days),
        }

    @staticmethod
    def _iter_managed(base: Path) -> Iterable[Path]:
        for entry in base.iterdir():
            if entry.is_file() and entry.suffix.lower() in MANAGED_SUFFIXES:
                yield entry

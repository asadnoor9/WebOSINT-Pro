"""Shared behaviour for every report writer.

Every writer takes the same scan-results mapping and produces exactly one
file. The parts that used to be copy-pasted into the controller for each
format -- creating the parent directory and tightening file permissions --
live here instead, so a new format cannot forget them.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Any


class BaseReport(ABC):
    """Base class for report writers.

    Subclasses set :attr:`extension` and implement :meth:`save`. Callers
    should prefer :meth:`write`, which adds directory creation and 0600
    permissions around ``save``.
    """

    #: File extension, without the leading dot.
    extension: str = ""
    #: Human-readable format name used in logs and CLI output.
    format_name: str = ""
    #: True when the writer needs an optional third-party dependency.
    requires_extra: str | None = None

    def __init__(self, results: dict[str, Any] | None = None) -> None:
        self.results: dict[str, Any] = results or {}

    # -- helpers available to every subclass -------------------------------

    @property
    def target(self) -> str:
        """Target recorded in the scan metadata."""
        meta = self.results.get("meta", {}) or {}
        return str(meta.get("target", "unknown"))

    @classmethod
    def default_stem(cls, target: str, when: datetime | None = None) -> str:
        """Deterministic, filesystem-safe basename for a report."""
        stamp = (when or datetime.now()).strftime("%Y%m%d_%H%M%S")
        safe = "".join(c if c.isalnum() else "_" for c in target) or "target"
        return f"webosint_{safe}_{stamp}"

    def filename(self, stem: str) -> str:
        return f"{stem}.{self.extension}" if self.extension else stem

    def write(self, path: str | Path) -> str:
        """Write the report, creating parents and restricting permissions.

        Reports routinely contain hostnames, addresses and evidence, so the
        file is owner-only. Permission failures are non-fatal because some
        filesystems do not support chmod.
        """
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        written = self.save(str(target))
        try:
            target.chmod(0o600)
        except OSError:
            pass
        return written or str(target)

    @abstractmethod
    def save(self, path: str) -> str:
        """Render the report to ``path`` and return the path written."""

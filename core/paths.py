"""Filesystem layout for everything WebOSINT Pro generates at runtime.

One module owns these paths so no part of the codebase invents its own
location. Nothing generated at runtime is written into the repository root:
reports, logs and caches all live under ``output/``, which Git ignores.

The root can be relocated with ``WEBOSINT_OUTPUT_DIR``, which is how the
systemd service keeps state outside the checkout.
"""

from __future__ import annotations

import os
from pathlib import Path

OUTPUT_DIR_ENV = "WEBOSINT_OUTPUT_DIR"

#: Repository root, resolved from this file rather than the process cwd.
PROJECT_ROOT = Path(__file__).resolve().parent.parent


def output_dir() -> Path:
    """Root of all generated artifacts."""
    override = os.environ.get(OUTPUT_DIR_ENV)
    return Path(override).expanduser() if override else PROJECT_ROOT / "output"


def reports_dir() -> Path:
    """Generated scan reports."""
    return output_dir() / "reports"


def logs_dir() -> Path:
    """Structured run logs."""
    return output_dir() / "logs"


def cache_dir() -> Path:
    """On-disk response and fingerprint caches."""
    return output_dir() / "cache"


def ensure(path: Path) -> Path:
    """Create ``path`` if needed and return it."""
    path.mkdir(parents=True, exist_ok=True)
    return path


def ensure_all() -> dict[str, Path]:
    """Create the whole output tree and return the resolved locations."""
    return {
        "output": ensure(output_dir()),
        "reports": ensure(reports_dir()),
        "logs": ensure(logs_dir()),
        "cache": ensure(cache_dir()),
    }


__all__ = [
    "OUTPUT_DIR_ENV",
    "PROJECT_ROOT",
    "cache_dir",
    "ensure",
    "ensure_all",
    "logs_dir",
    "output_dir",
    "reports_dir",
]

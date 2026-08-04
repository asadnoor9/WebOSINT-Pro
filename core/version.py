"""Single source of truth for the WebOSINT Pro version."""

from __future__ import annotations

__version__ = "2.0.0"


def version_string() -> str:
    """Return a human-readable version banner string."""
    return f"WebOSINT Pro {__version__}"

"""Format selection and dispatch for report writing.

The controller used to hold a hand-maintained list of ``(extension, module
path, class name)`` tuples and import them by string, so adding a format
meant editing the controller and a typo failed at runtime. Formats are
declared here once instead, and the controller only supplies results and a
destination.

Heavy writers (PDF, Word) are imported lazily so a checkout without the
optional ``reports`` extra still starts instantly.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

from reporting.base import BaseReport

LOG = logging.getLogger(__name__)


def _json() -> type[BaseReport]:
    from reporting.json import JSONReport

    return JSONReport


def _html() -> type[BaseReport]:
    from reporting.html import HTMLReport

    return HTMLReport


def _markdown() -> type[BaseReport]:
    from reporting.markdown import MarkdownReport

    return MarkdownReport


def _csv() -> type[BaseReport]:
    from reporting.csv import CSVReport

    return CSVReport


def _pdf() -> type[BaseReport]:
    from reporting.pdf import PDFReport

    return PDFReport


def _docx() -> type[BaseReport]:
    from reporting.docx import DocxReport

    return DocxReport


#: Canonical format name -> lazy writer loader.
WRITERS: dict[str, Callable[[], type[BaseReport]]] = {
    "json": _json,
    "html": _html,
    "markdown": _markdown,
    "csv": _csv,
    "pdf": _pdf,
    "docx": _docx,
}

#: Names the CLI accepts that expand to several formats.
GROUPS: dict[str, tuple[str, ...]] = {
    "none": (),
    "both": ("json", "html"),
    "all": ("json", "html", "markdown", "csv", "docx", "pdf"),
}

#: Every value ``--output`` accepts.
CHOICES: tuple[str, ...] = tuple(WRITERS) + tuple(GROUPS)


def resolve_formats(requested: str | list[str] | None) -> list[str]:
    """Expand a CLI value into an ordered, de-duplicated format list.

    Unknown names are dropped rather than raised, so a stale config cannot
    discard the results of a completed scan.
    """
    if requested is None:
        return ["json"]
    names = [requested] if isinstance(requested, str) else list(requested)

    resolved: list[str] = []
    for raw in names:
        name = str(raw).strip().lower()
        for candidate in GROUPS.get(name, (name,)):
            if candidate in WRITERS:
                if candidate not in resolved:
                    resolved.append(candidate)
            else:
                LOG.warning("ignoring unknown report format %r", candidate)
    return resolved


def writer_for(name: str) -> type[BaseReport]:
    """Return the writer class for a canonical format name."""
    try:
        return WRITERS[name]()
    except KeyError as exc:
        raise ValueError(f"unknown report format: {name!r}") from exc


def write_reports(
    results: dict[str, Any],
    output_dir: str | Path,
    *,
    formats: str | list[str] | None = "json",
    stem: str | None = None,
    logger: Any | None = None,
) -> list[str]:
    """Write every requested format and return the paths written.

    One failing writer never prevents the others from running: a missing
    optional dependency should cost you the PDF, not the whole report set.
    """
    names = resolve_formats(formats)
    if not names:
        return []

    target_dir = Path(output_dir)
    meta = results.get("meta", {}) or {}
    basename = stem or BaseReport.default_stem(str(meta.get("target", "")))
    written: list[str] = []

    for name in names:
        try:
            writer = writer_for(name)(results)
            written.append(writer.write(target_dir / writer.filename(basename)))
        except Exception as exc:
            message = f"{name} report failed: {exc}"
            if logger is not None:
                logger.error(message)
            else:
                LOG.error(message)

    return written


__all__ = [
    "CHOICES",
    "GROUPS",
    "WRITERS",
    "resolve_formats",
    "write_reports",
    "writer_for",
]

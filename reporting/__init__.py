"""Report generation for WebOSINT Pro.

One package owns every output format. Each writer subclasses
:class:`reporting.base.BaseReport`, and :mod:`reporting.export` maps CLI
format names onto those writers:

    from reporting.export import write_reports

    write_reports(results, "output/reports", formats="all")

Light writers are re-exported here. PDF and Word are deliberately *not*
imported eagerly because they depend on the optional ``reports`` extra.
"""

from reporting.base import BaseReport
from reporting.csv import CSVReport
from reporting.export import CHOICES, resolve_formats, write_reports, writer_for
from reporting.html import HTMLReport
from reporting.json import JSONReport
from reporting.markdown import MarkdownReport

__all__ = [
    "CHOICES",
    "BaseReport",
    "CSVReport",
    "HTMLReport",
    "JSONReport",
    "MarkdownReport",
    "resolve_formats",
    "write_reports",
    "writer_for",
]

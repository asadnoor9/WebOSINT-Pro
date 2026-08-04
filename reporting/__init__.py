"""
Compatibility facade for the legacy `reporting.*` import path.

The concrete report generators live in `reports/`.
"""

from reports.html_report import HTMLReport
from reports.json_report import JSONReport
from reports.markdown_report import MarkdownReport

__all__ = ["HTMLReport", "JSONReport", "MarkdownReport"]

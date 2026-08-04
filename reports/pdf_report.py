"""
WebOSINT Pro - PDF report generator

Requires reportlab (the optional 'reports' extra). Imported lazily so the
core tool works without it installed.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from reports.enrichment import enrich_results

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

SEVERITY_COLOR = {
    "critical": "#b00020",
    "high": "#d95f02",
    "medium": "#b58900",
    "low": "#2e7d32",
    "info": "#455a64",
}


class PDFReport:
    def __init__(self, results: dict[str, Any]):
        self.results = results
        self.meta = results.get("meta", {})
        self.summary = results.get("summary", {})
        self.findings = results.get("findings", {})
        self.errors = results.get("errors", {})
        self.normalized = results.get("normalized_findings", [])

    def save(self, path: str) -> str:
        try:
            from reportlab.lib import colors
            from reportlab.lib.enums import TA_LEFT
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
            from reportlab.lib.units import mm
            from reportlab.platypus import (
                PageBreak,
                Paragraph,
                SimpleDocTemplate,
                Spacer,
                Table,
                TableStyle,
            )
        except ImportError as exc:  # pragma: no cover - depends on optional extra
            raise RuntimeError(
                "PDF export needs reportlab. Install the extra: pip install '.[reports]'"
            ) from exc

        enrichment = enrich_results(self.results)
        styles = getSampleStyleSheet()
        body = ParagraphStyle(
            "body", parent=styles["BodyText"], fontSize=8.5, leading=11, alignment=TA_LEFT
        )
        h1 = ParagraphStyle("h1", parent=styles["Heading1"], fontSize=15, spaceAfter=8)
        h2 = ParagraphStyle("h2", parent=styles["Heading2"], fontSize=11.5, spaceAfter=5)

        doc = SimpleDocTemplate(
            path,
            pagesize=A4,
            title=f"WebOSINT Pro Report - {self.meta.get('target', '')}",
            author="WebOSINT Pro",
            leftMargin=16 * mm,
            rightMargin=16 * mm,
            topMargin=16 * mm,
            bottomMargin=16 * mm,
        )

        story: list[Any] = [Paragraph("WebOSINT Pro Report", styles["Title"]), Spacer(1, 6)]

        if not self.meta.get("results_trusted", True):
            story.append(
                Paragraph(
                    '<font color="#b00020"><b>TLS verification was disabled. '
                    "All findings are UNTRUSTED.</b></font>",
                    body,
                )
            )
            story.append(Spacer(1, 6))

        # ── Overview ──────────────────────────────────────────────────────────
        story.append(Paragraph("Overview", h1))
        overview = [
            ["Target", str(self.meta.get("target", "unknown"))],
            ["Mode", str(self.meta.get("mode", "passive"))],
            ["Detail level", str(self.meta.get("detail_level", "standard"))],
            ["TLS verified", str(self.meta.get("tls_verified", True))],
            ["Generated", datetime.now().isoformat(timespec="seconds")],
            ["Modules run", str(len(self.meta.get("modules_run", [])))],
            ["Total findings", str(self.summary.get("total_findings", 0))],
        ]
        table = Table(overview, colWidths=[45 * mm, 120 * mm])
        table.setStyle(
            TableStyle(
                [
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cfd8dc")),
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eceff1")),
                    ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ]
            )
        )
        story.extend([table, Spacer(1, 10)])

        # ── Severity summary ──────────────────────────────────────────────────
        story.append(Paragraph("Severity summary", h1))
        counts = self.summary.get("severity_counts", self.summary.get("risk_counts", {}))
        sev_rows = [["Severity", "Count"]]
        sev_rows += [[level.title(), str(counts.get(level, 0))] for level in SEVERITY_ORDER]
        sev_table = Table(sev_rows, colWidths=[45 * mm, 25 * mm])
        sev_table.setStyle(
            TableStyle(
                [
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cfd8dc")),
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#37474f")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                ]
            )
        )
        story.extend([sev_table, Spacer(1, 10)])

        # ── Findings ──────────────────────────────────────────────────────────
        story.append(Paragraph("Findings", h1))
        if self.normalized:
            rows: list[list[Any]] = [
                [
                    Paragraph("<b>Sev</b>", body),
                    Paragraph("<b>Title</b>", body),
                    Paragraph("<b>Value</b>", body),
                    Paragraph("<b>Status</b>", body),
                ]
            ]
            for finding in self.normalized:
                severity = str(finding.get("severity", "info")).lower()
                color = SEVERITY_COLOR.get(severity, "#455a64")
                rows.append(
                    [
                        Paragraph(
                            f'<font color="{color}"><b>{_esc(severity.upper())}</b></font>', body
                        ),
                        Paragraph(_esc(str(finding.get("title", ""))), body),
                        Paragraph(_esc(_flatten(finding.get("value", ""))[:300]), body),
                        Paragraph(_esc(str(finding.get("status", ""))), body),
                    ]
                )
            findings_table = Table(
                rows, colWidths=[18 * mm, 45 * mm, 85 * mm, 22 * mm], repeatRows=1
            )
            findings_table.setStyle(
                TableStyle(
                    [
                        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cfd8dc")),
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eceff1")),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ]
                )
            )
            story.append(findings_table)
        else:
            for module, data in self.findings.items():
                story.append(Paragraph(_esc(module), h2))
                for line in _render_lines(data):
                    story.append(Paragraph(_esc(line), body))
                story.append(Spacer(1, 6))

        # ── Remediation ───────────────────────────────────────────────────────
        remediation = enrichment.get("remediation_intelligence", [])
        if remediation:
            story.extend([PageBreak(), Paragraph("Remediation intelligence", h1)])
            for item in remediation:
                story.append(Paragraph(_esc(item.get("issue_title", "Issue")), h2))
                for label, key in [
                    ("Severity", "severity"),
                    ("Confidence", "confidence"),
                    ("Why risky", "why_risky"),
                    ("Impact", "impact"),
                    ("Recommended fix", "recommended_fix"),
                ]:
                    value = item.get(key)
                    if value:
                        story.append(Paragraph(f"<b>{label}:</b> {_esc(str(value))}", body))
                story.append(Spacer(1, 6))

        if self.errors:
            story.append(Paragraph("Module errors", h1))
            for module, message in sorted(self.errors.items()):
                story.append(Paragraph(f"<b>{_esc(module)}:</b> {_esc(str(message))}", body))

        doc.build(story, onLaterPages=_footer, onFirstPage=_footer)
        return path


def _footer(canvas, doc) -> None:  # noqa: ANN001
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillGray(0.45)
    canvas.drawString(16, 12, "WebOSINT Pro - authorized security testing only")
    canvas.drawRightString(canvas._pagesize[0] - 16, 12, f"Page {doc.page}")
    canvas.restoreState()


def _esc(text: str) -> str:
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _flatten(value: Any) -> str:
    if isinstance(value, (list, tuple, set)):
        return "; ".join(_flatten(v) for v in value)
    if isinstance(value, dict):
        return "; ".join(f"{k}={_flatten(v)}" for k, v in sorted(value.items()))
    return str(value)


def _render_lines(data: Any, depth: int = 0) -> list[str]:
    pad = "&nbsp;" * (depth * 4)
    out: list[str] = []
    if isinstance(data, dict):
        for key, value in data.items():
            if str(key).startswith("_") or value in (None, "", [], {}):
                continue
            if isinstance(value, (dict, list)):
                out.append(f"{pad}{key}:")
                out.extend(_render_lines(value, depth + 1))
            else:
                out.append(f"{pad}{key}: {str(value)[:300]}")
    elif isinstance(data, list):
        out.extend(f"{pad}{_flatten(item)[:300]}" for item in data[:60])
    else:
        out.append(f"{pad}{str(data)[:300]}")
    return out or [f"{pad}No findings"]

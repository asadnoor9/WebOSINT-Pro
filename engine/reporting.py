"""
Multi-audience report engine.

One scan produces several documents because the audiences differ:

* **Executive**  - posture, trend and business risk; no jargon.
* **Technical**  - every finding with full evidence and provenance.
* **SOC**        - detection-oriented: what to watch, what to escalate.
* **Developer**  - ranked, actionable fixes with concrete remediation.
* **Dashboard**  - the risk overview rendered as a standalone HTML page.

Heavy exporters (PDF, Word, Excel) are optional imports. A missing exporter
produces a clear, actionable message instead of aborting the report run.
"""

from __future__ import annotations

import csv
import html
import io
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from engine.correlation import Analysis, analyse

LOG = logging.getLogger(__name__)


class Audience(str, Enum):
    EXECUTIVE = "executive"
    TECHNICAL = "technical"
    SOC = "soc"
    DEVELOPER = "developer"
    DASHBOARD = "dashboard"


SEVERITY_COLOURS = {
    "critical": "#b3202c",
    "high": "#d9534f",
    "medium": "#e0a800",
    "low": "#4a90d9",
    "info": "#6c757d",
}


@dataclass(slots=True)
class ReportBundle:
    """Everything a renderer needs, computed once and shared."""

    result: Any
    analysis: Analysis
    generated_at: str

    @classmethod
    def build(cls, result: Any) -> ReportBundle:
        return cls(
            result=result,
            analysis=analyse(result),
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        )

    def to_dict(self) -> dict[str, Any]:
        payload = self.result.to_dict()
        payload["analysis"] = self.analysis.to_dict()
        payload["generated_at"] = self.generated_at
        return payload


# --- JSON -------------------------------------------------------------------


def render_json(bundle: ReportBundle) -> str:
    """Deterministic JSON: sorted keys so diffs between scans are meaningful."""
    return json.dumps(bundle.to_dict(), indent=2, sort_keys=True, default=str)


# --- Markdown ---------------------------------------------------------------


def render_markdown(bundle: ReportBundle, audience: Audience = Audience.TECHNICAL) -> str:
    result = bundle.result
    analysis = bundle.analysis
    counts = result.severity_counts()
    lines: list[str] = []

    lines.append(f"# WebOSINT Pro report - {result.target}")
    lines.append("")
    lines.append(f"*Generated {bundle.generated_at} - audience: {audience.value}*")
    lines.append("")

    lines.append("## Executive summary")
    lines.append("")
    lines.append(analysis.executive_summary)
    lines.append("")

    lines.append("## Risk overview")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("| --- | --- |")
    lines.append(f"| Risk score | {result.risk_score:.1f} / 100 |")
    lines.append(f"| Attack surface | {result.surface.value.replace('_', ' ')} |")
    lines.append(f"| Scan duration | {result.duration_ms / 1000:.1f}s |")
    for severity in ("critical", "high", "medium", "low", "info"):
        lines.append(f"| {severity.title()} findings | {counts[severity]} |")
    lines.append("")

    if result.technologies:
        lines.append("## Technology profile")
        lines.append("")
        lines.append("| Technology | Category | Version | Confidence |")
        lines.append("| --- | --- | --- | --- |")
        for tech in result.technologies:
            lines.append(
                f"| {tech.name} | {tech.category} | {tech.version or '-'} "
                f"| {tech.confidence:.0f}% |"
            )
        lines.append("")

    if audience in (Audience.SOC, Audience.TECHNICAL):
        lines.append("## SOC summary")
        lines.append("")
        lines.append(analysis.soc_summary)
        lines.append("")

    if audience in (Audience.DEVELOPER, Audience.TECHNICAL) and analysis.priorities:
        lines.append("## Prioritized remediation")
        lines.append("")
        for item in analysis.priorities:
            lines.append(
                f"{item['rank']}. **{item['title']}** ({item['severity']}, "
                f"confidence {item['confidence']:.0f}%)"
            )
            lines.append(f"   - {item['remediation']}")
        lines.append("")

    if audience is not Audience.EXECUTIVE:
        lines.append("## Findings")
        lines.append("")
        if not result.reported:
            lines.append("No findings met the reporting confidence threshold.")
            lines.append("")
        for finding in result.reported:
            lines.append(f"### {finding.title}")
            lines.append("")
            lines.append(
                f"- **Severity:** {finding.severity.value} "
                f"| **Confidence:** {finding.confidence:.0f}% "
                f"| **Verified:** {'yes' if finding.verified else 'no'}"
            )
            lines.append(
                f"- **Risk score:** {finding.risk_score} "
                f"| **Exploitability:** {finding.exploitability.value} "
                f"| **False-positive probability:** "
                f"{finding.false_positive_probability:.0%}"
            )
            lines.append(f"- **Validation:** {finding.validation_method.value}")
            lines.append(f"- **Source plugin:** {finding.plugin}")
            if finding.cwe:
                lines.append(f"- **CWE:** {', '.join(finding.cwe)}")
            if finding.owasp:
                lines.append(f"- **OWASP:** {', '.join(finding.owasp)}")
            if finding.mitre:
                lines.append(f"- **MITRE ATT&CK:** {', '.join(finding.mitre)}")
            if finding.description:
                lines.append("")
                lines.append(finding.description)
            if finding.evidence:
                lines.append("")
                lines.append("**Evidence**")
                lines.append("")
                for evidence in finding.evidence:
                    lines.append(
                        f"- `{evidence.kind.value}` {evidence.summary}"
                        + (f": `{evidence.value}`" if evidence.value else "")
                    )
            lines.append("")

    if result.plan and result.plan.skipped and audience is Audience.TECHNICAL:
        lines.append("## Plugins not executed")
        lines.append("")
        lines.append(
            "These were skipped deliberately: the observed technology profile made "
            "them inapplicable, which is why this scan finished quickly."
        )
        lines.append("")
        for decision in result.plan.skipped:
            lines.append(f"- **{decision.plugin}**: {decision.reason}")
        lines.append("")

    if analysis.false_positive_candidates and audience in (Audience.SOC, Audience.TECHNICAL):
        lines.append("## Findings flagged for analyst review")
        lines.append("")
        for candidate in analysis.false_positive_candidates:
            lines.append(
                f"- **{candidate['title']}** ({candidate['severity']}): "
                + "; ".join(candidate["reasons"])
            )
        lines.append("")

    compliance = result.compliance.get("frameworks", {})
    if compliance and audience is not Audience.EXECUTIVE:
        lines.append("## Control framework mapping")
        lines.append("")
        for key, block in compliance.items():
            controls = block.get("controls", {})
            if not controls:
                continue
            lines.append(f"**{block.get('name', key)}**")
            lines.append("")
            for control, count in controls.items():
                lines.append(f"- {control} ({count} finding(s))")
            lines.append("")

    return "\n".join(lines).rstrip() + "\n"


# --- CSV --------------------------------------------------------------------


def render_csv(bundle: ReportBundle) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(
        [
            "target",
            "plugin",
            "title",
            "severity",
            "confidence",
            "verified",
            "risk_score",
            "exploitability",
            "false_positive_probability",
            "validation_method",
            "evidence_kinds",
            "cwe",
            "owasp",
            "mitre",
        ]
    )
    for finding in bundle.result.reported:
        writer.writerow(
            [
                bundle.result.target,
                finding.plugin,
                finding.title,
                finding.severity.value,
                f"{finding.confidence:.1f}",
                "yes" if finding.verified else "no",
                finding.risk_score,
                finding.exploitability.value,
                f"{finding.false_positive_probability:.3f}",
                finding.validation_method.value,
                "|".join(sorted(kind.value for kind in finding.evidence_kinds)),
                "|".join(finding.cwe),
                "|".join(finding.owasp),
                "|".join(finding.mitre),
            ]
        )
    return buffer.getvalue()


# --- HTML -------------------------------------------------------------------

_HTML_STYLE = """
:root { color-scheme: dark; }
body { margin:0; padding:2rem; background:#0f1115; color:#e6e6e6;
  font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; line-height:1.6; }
.wrap { max-width:1100px; margin:0 auto; }
h1,h2,h3 { color:#fff; line-height:1.25; }
h1 { border-bottom:2px solid #2a2f3a; padding-bottom:.5rem; }
h2 { margin-top:2.5rem; border-bottom:1px solid #2a2f3a; padding-bottom:.35rem; }
.meta { color:#8b93a1; font-size:.9rem; }
.cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:1rem; margin:1.5rem 0; }
.card { background:#171a21; border:1px solid #262b36; border-radius:10px; padding:1rem; text-align:center; }
.card .n { font-size:2rem; font-weight:700; display:block; }
.card .l { color:#8b93a1; font-size:.8rem; text-transform:uppercase; letter-spacing:.05em; }
.gauge { height:12px; background:#262b36; border-radius:6px; overflow:hidden; margin:.5rem 0 1.5rem; }
.gauge > span { display:block; height:100%; border-radius:6px; }
table { width:100%; border-collapse:collapse; margin:1rem 0; font-size:.92rem; }
th,td { text-align:left; padding:.6rem .7rem; border-bottom:1px solid #262b36; vertical-align:top; }
th { color:#8b93a1; font-weight:600; text-transform:uppercase; font-size:.75rem; letter-spacing:.04em; }
.pill { display:inline-block; padding:.15rem .55rem; border-radius:999px; font-size:.75rem;
  font-weight:600; color:#fff; text-transform:uppercase; }
.finding { background:#171a21; border:1px solid #262b36; border-left-width:4px;
  border-radius:8px; padding:1rem 1.2rem; margin:1rem 0; }
.evidence { background:#0f1115; border:1px solid #262b36; border-radius:6px;
  padding:.6rem .8rem; margin:.4rem 0; font-family:ui-monospace,Menlo,monospace; font-size:.82rem; }
.kind { color:#7aa2f7; font-weight:600; }
.summary { background:#171a21; border:1px solid #262b36; border-radius:10px; padding:1.2rem 1.4rem; }
.muted { color:#8b93a1; }
footer { margin-top:3rem; padding-top:1rem; border-top:1px solid #262b36; color:#8b93a1; font-size:.85rem; }
"""


def _bar(counts: dict[str, int]) -> str:
    total = sum(counts.values()) or 1
    segments = []
    for severity in ("critical", "high", "medium", "low", "info"):
        count = counts[severity]
        if not count:
            continue
        width = 100.0 * count / total
        segments.append(
            f'<span style="width:{width:.1f}%;background:{SEVERITY_COLOURS[severity]};'
            f'float:left" title="{severity}: {count}"></span>'
        )
    return '<div class="gauge">' + "".join(segments) + "</div>"


def render_html(bundle: ReportBundle, audience: Audience = Audience.TECHNICAL) -> str:
    result = bundle.result
    analysis = bundle.analysis
    counts = result.severity_counts()
    esc = html.escape

    parts: list[str] = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        f"<title>WebOSINT Pro - {esc(result.target)}</title>",
        f"<style>{_HTML_STYLE}</style></head><body><div class='wrap'>",
        f"<h1>{esc(result.target)}</h1>",
        f"<p class='meta'>Generated {esc(bundle.generated_at)} &middot; "
        f"{esc(audience.value)} report &middot; "
        f"surface: {esc(result.surface.value.replace('_', ' '))} &middot; "
        f"{result.duration_ms / 1000:.1f}s</p>",
    ]

    parts.append("<div class='cards'>")
    parts.append(
        f"<div class='card'><span class='n'>{result.risk_score:.0f}</span>"
        f"<span class='l'>Risk score</span></div>"
    )
    for severity in ("critical", "high", "medium", "low", "info"):
        parts.append(
            f"<div class='card'><span class='n' style='color:{SEVERITY_COLOURS[severity]}'>"
            f"{counts[severity]}</span><span class='l'>{severity}</span></div>"
        )
    parts.append("</div>")
    parts.append(_bar(counts))

    parts.append("<h2>Executive summary</h2>")
    parts.append(f"<div class='summary'>{esc(analysis.executive_summary)}</div>")

    if audience in (Audience.SOC, Audience.TECHNICAL, Audience.DASHBOARD):
        parts.append("<h2>SOC summary</h2>")
        parts.append(f"<div class='summary'>{esc(analysis.soc_summary)}</div>")

    if result.technologies:
        parts.append(
            "<h2>Technology profile</h2><table><tr><th>Technology</th>"
            "<th>Category</th><th>Version</th><th>Confidence</th></tr>"
        )
        for tech in result.technologies:
            parts.append(
                f"<tr><td>{esc(tech.name)}</td><td>{esc(tech.category)}</td>"
                f"<td>{esc(tech.version or '-')}</td><td>{tech.confidence:.0f}%</td></tr>"
            )
        parts.append("</table>")

    if analysis.priorities:
        parts.append(
            "<h2>Prioritized remediation</h2><table>"
            "<tr><th>#</th><th>Finding</th><th>Severity</th>"
            "<th>Confidence</th><th>Recommended action</th></tr>"
        )
        for item in analysis.priorities:
            colour = SEVERITY_COLOURS.get(item["severity"], "#6c757d")
            parts.append(
                f"<tr><td>{item['rank']}</td><td>{esc(item['title'])}</td>"
                f"<td><span class='pill' style='background:{colour}'>"
                f"{esc(item['severity'])}</span></td>"
                f"<td>{item['confidence']:.0f}%</td>"
                f"<td>{esc(item['remediation'])}</td></tr>"
            )
        parts.append("</table>")

    if audience is not Audience.EXECUTIVE:
        parts.append("<h2>Findings</h2>")
        if not result.reported:
            parts.append("<p class='muted'>No findings met the reporting confidence threshold.</p>")
        for finding in result.reported:
            colour = SEVERITY_COLOURS.get(finding.severity.value, "#6c757d")
            parts.append(f"<div class='finding' style='border-left-color:{colour}'>")
            parts.append(
                f"<h3>{esc(finding.title)} "
                f"<span class='pill' style='background:{colour}'>"
                f"{esc(finding.severity.value)}</span></h3>"
            )
            parts.append(
                f"<p class='meta'>Confidence {finding.confidence:.0f}% &middot; "
                f"{'verified' if finding.verified else 'unverified'} &middot; "
                f"risk {finding.risk_score} &middot; "
                f"exploitability {esc(finding.exploitability.value)} &middot; "
                f"FP probability {finding.false_positive_probability:.0%} &middot; "
                f"validation {esc(finding.validation_method.value)} &middot; "
                f"plugin {esc(finding.plugin)}</p>"
            )
            if finding.description:
                parts.append(f"<p>{esc(finding.description)}</p>")
            mappings = []
            if finding.cwe:
                mappings.append("CWE: " + ", ".join(finding.cwe))
            if finding.owasp:
                mappings.append("OWASP: " + ", ".join(finding.owasp))
            if finding.mitre:
                mappings.append("ATT&CK: " + ", ".join(finding.mitre))
            if mappings:
                parts.append(f"<p class='meta'>{esc(' | '.join(mappings))}</p>")
            for evidence in finding.evidence:
                value = f": {esc(evidence.value)}" if evidence.value else ""
                parts.append(
                    f"<div class='evidence'><span class='kind'>"
                    f"{esc(evidence.kind.value)}</span> {esc(evidence.summary)}{value}</div>"
                )
            parts.append("</div>")

    if result.plan and result.plan.skipped and audience is Audience.TECHNICAL:
        parts.append("<h2>Plugins not executed</h2>")
        parts.append(
            "<p class='muted'>Skipped deliberately because the observed technology "
            "profile made them inapplicable.</p><table><tr><th>Plugin</th><th>Reason</th></tr>"
        )
        for decision in result.plan.skipped:
            parts.append(f"<tr><td>{esc(decision.plugin)}</td><td>{esc(decision.reason)}</td></tr>")
        parts.append("</table>")

    frameworks = result.compliance.get("frameworks", {})
    if frameworks and audience is not Audience.EXECUTIVE:
        parts.append(
            "<h2>Control framework mapping</h2><table>"
            "<tr><th>Framework</th><th>Control</th><th>Findings</th></tr>"
        )
        for key, block in frameworks.items():
            for control, count in block.get("controls", {}).items():
                parts.append(
                    f"<tr><td>{esc(block.get('name', key))}</td>"
                    f"<td>{esc(control)}</td><td>{count}</td></tr>"
                )
        parts.append("</table>")

    parts.append(
        "<footer>Generated by WebOSINT Pro. Every finding above is supported by the "
        "evidence shown; findings whose evidence was too weak to assert confidently "
        "were withheld rather than reported.</footer>"
    )
    parts.append("</div></body></html>")
    return "".join(parts)


# --- Excel ------------------------------------------------------------------


def render_excel(bundle: ReportBundle, path: Path) -> Path:
    """Write a multi-sheet workbook: findings, technologies, plan, compliance."""
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Font, PatternFill
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise RuntimeError(
            "Excel export needs openpyxl. Install it with: pip install openpyxl"
        ) from exc

    result = bundle.result
    workbook = Workbook()
    header_font = Font(bold=True, color="FFFFFF")
    header_fill = PatternFill("solid", start_color="1F2937")

    def write_sheet(title: str, headers: list[str], rows: list[list[Any]]) -> None:
        sheet = workbook.create_sheet(title=title[:31])
        sheet.append(headers)
        for cell in sheet[1]:
            cell.font = header_font
            cell.fill = header_fill
        for row in rows:
            sheet.append(row)
        for index, header in enumerate(headers, start=1):
            longest = max([len(str(header))] + [len(str(row[index - 1])) for row in rows] or [10])
            sheet.column_dimensions[sheet.cell(row=1, column=index).column_letter].width = min(
                60, max(12, longest + 2)
            )
        sheet.freeze_panes = "A2"

    workbook.remove(workbook.active)

    write_sheet(
        "Summary",
        ["Metric", "Value"],
        [
            ["Target", result.target],
            ["Generated", bundle.generated_at],
            ["Risk score", result.risk_score],
            ["Attack surface", result.surface.value],
            ["Duration (s)", round(result.duration_ms / 1000, 1)],
            *[[f"{k.title()} findings", v] for k, v in result.severity_counts().items()],
        ],
    )

    write_sheet(
        "Findings",
        [
            "Title",
            "Severity",
            "Confidence %",
            "Verified",
            "Risk",
            "Exploitability",
            "FP probability",
            "Validation",
            "Plugin",
            "Evidence kinds",
            "CWE",
            "OWASP",
        ],
        [
            [
                finding.title,
                finding.severity.value,
                round(finding.confidence, 1),
                "yes" if finding.verified else "no",
                finding.risk_score,
                finding.exploitability.value,
                round(finding.false_positive_probability, 3),
                finding.validation_method.value,
                finding.plugin,
                ", ".join(sorted(kind.value for kind in finding.evidence_kinds)),
                ", ".join(finding.cwe),
                ", ".join(finding.owasp),
            ]
            for finding in result.reported
        ],
    )

    write_sheet(
        "Technologies",
        ["Name", "Category", "Version", "Confidence %"],
        [
            [t.name, t.category, t.version or "", round(t.confidence, 1)]
            for t in result.technologies
        ],
    )

    if result.plan:
        write_sheet(
            "Scan plan",
            ["Plugin", "Executed", "Reason"],
            [[d.plugin, "yes" if d.selected else "no", d.reason] for d in result.plan.decisions],
        )

    compliance_rows = [
        [block.get("name", key), control, count]
        for key, block in result.compliance.get("frameworks", {}).items()
        for control, count in block.get("controls", {}).items()
    ]
    if compliance_rows:
        write_sheet("Compliance", ["Framework", "Control", "Findings"], compliance_rows)

    path.parent.mkdir(parents=True, exist_ok=True)
    workbook.save(path)
    return path


# --- PDF --------------------------------------------------------------------


def render_pdf(bundle: ReportBundle, path: Path, audience: Audience = Audience.EXECUTIVE) -> Path:
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise RuntimeError(
            "PDF export needs reportlab. Install the extra: pip install '.[reports]'"
        ) from exc

    result = bundle.result
    styles = getSampleStyleSheet()
    path.parent.mkdir(parents=True, exist_ok=True)
    document = SimpleDocTemplate(str(path), pagesize=A4, title=f"WebOSINT Pro - {result.target}")

    story: list[Any] = [
        Paragraph(f"WebOSINT Pro report: {html.escape(result.target)}", styles["Title"]),
        Paragraph(bundle.generated_at, styles["Normal"]),
        Spacer(1, 16),
        Paragraph("Executive summary", styles["Heading2"]),
        Paragraph(html.escape(bundle.analysis.executive_summary), styles["BodyText"]),
        Spacer(1, 12),
    ]

    if bundle.analysis.priorities:
        story.append(Paragraph("Prioritized remediation", styles["Heading2"]))
        for item in bundle.analysis.priorities:
            story.append(
                Paragraph(
                    f"<b>{item['rank']}. {html.escape(item['title'])}</b> "
                    f"({item['severity']}, {item['confidence']:.0f}% confidence)<br/>"
                    f"{html.escape(item['remediation'])}",
                    styles["BodyText"],
                )
            )
            story.append(Spacer(1, 6))

    if audience is not Audience.EXECUTIVE:
        story.append(Paragraph("Findings", styles["Heading2"]))
        for finding in result.reported:
            story.append(
                Paragraph(
                    f"<b>{html.escape(finding.title)}</b> - {finding.severity.value}, "
                    f"confidence {finding.confidence:.0f}%, risk {finding.risk_score}",
                    styles["BodyText"],
                )
            )

    document.build(story)
    return path


# --- orchestration ----------------------------------------------------------

TEXT_RENDERERS = {
    "json": (render_json, "json"),
    "md": (render_markdown, "md"),
    "html": (render_html, "html"),
    "csv": (render_csv, "csv"),
}


def generate(
    result: Any,
    output_dir: Path | str,
    *,
    formats: list[str] | None = None,
    audience: Audience = Audience.TECHNICAL,
    stem: str = "",
) -> dict[str, Any]:
    """Render every requested format, reporting per-format success.

    A failing optional exporter never prevents the others from being written.
    """
    bundle = ReportBundle.build(result)
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)

    safe_target = "".join(c if c.isalnum() else "_" for c in result.target)
    base = stem or f"webosint_{safe_target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    requested = formats or ["json", "md", "html", "csv"]

    written: list[str] = []
    failed: dict[str, str] = {}

    for fmt in requested:
        key = fmt.strip().lower()
        path = directory / f"{base}.{key}"
        try:
            if key in TEXT_RENDERERS:
                renderer, extension = TEXT_RENDERERS[key]
                content = renderer(bundle, audience) if key in ("md", "html") else renderer(bundle)
                path = directory / f"{base}.{extension}"
                path.write_text(content, encoding="utf-8")
            elif key in ("xlsx", "excel"):
                path = render_excel(bundle, directory / f"{base}.xlsx")
            elif key == "pdf":
                path = render_pdf(bundle, path, audience)
            else:
                failed[key] = f"Unknown report format: {key}"
                continue
            written.append(str(path))
        except Exception as exc:  # noqa: BLE001 - one bad format must not stop the rest
            LOG.warning("Could not write the %s report: %s", key, exc)
            failed[key] = str(exc)

    return {"written": written, "failed": failed, "bundle": bundle}


def generate_all_audiences(
    result: Any, output_dir: Path | str, *, formats: list[str] | None = None
) -> dict[str, Any]:
    """Produce the executive, technical, SOC and developer variants at once."""
    outputs: dict[str, Any] = {}
    for audience in (
        Audience.EXECUTIVE,
        Audience.TECHNICAL,
        Audience.SOC,
        Audience.DEVELOPER,
    ):
        safe_target = "".join(c if c.isalnum() else "_" for c in result.target)
        stem = f"webosint_{safe_target}_{audience.value}"
        outputs[audience.value] = generate(
            result, output_dir, formats=formats, audience=audience, stem=stem
        )
    return outputs

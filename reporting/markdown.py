"""Markdown report generator."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from reporting.base import BaseReport
from reporting.enrichment import enrich_results


class MarkdownReport(BaseReport):
    extension = "md"
    format_name = "Markdown"

    def save(self, path: str) -> str:
        with open(path, "w", encoding="utf-8") as f:
            f.write(self._render())
        return path

    def _render(self) -> str:
        meta = self.results.get("meta", {})
        summary = self.results.get("summary", {})
        findings = self.results.get("findings", {})
        errors = self.results.get("errors", {})
        enrichment = enrich_results(self.results)

        lines = [
            "# WebOSINT Pro Report",
            "",
            f"- Target: `{meta.get('target', 'unknown')}`",
            f"- Profile: `{meta.get('profile', 'medium')}`",
            f"- Generated: `{datetime.now().isoformat()}`",
            f"- Session: `{meta.get('session_id', '')}`",
            f"- Total findings: `{summary.get('total_findings', 0)}`",
            "",
            "## Severity Summary",
            "",
        ]
        risks = summary.get("risk_counts", {})
        for level in ("critical", "high", "medium", "low", "info"):
            lines.append(f"- {level.title()}: `{risks.get(level, 0)}`")

        lines.extend(self._render_remediation(enrichment))
        lines.extend(self._render_enrichment_sections(enrichment))

        lines.extend(["", "## Findings", ""])
        for module, data in findings.items():
            lines.extend([f"### {module}", ""])
            lines.extend(self._render_value(data))
            lines.append("")

        if errors:
            lines.extend(["## Module Errors", ""])
            for module, error in errors.items():
                lines.append(f"- `{module}`: {error}")
            lines.append("")

        return "\n".join(lines)

    def _render_remediation(self, enrichment: dict[str, Any]) -> list[str]:
        lines = ["", "## Remediation Intelligence", ""]
        items = enrichment.get("remediation_intelligence", [])
        if not items:
            return [*lines, "No remediation priorities were generated.", ""]
        for item in items:
            lines.extend(
                [
                    f"### {item.get('issue_title', 'Issue')}",
                    "",
                    f"- Module: `{item.get('module', '')}`",
                    f"- Severity: `{item.get('severity', '')}`",
                    f"- Confidence: `{item.get('confidence', '')}`",
                    f"- CWE: `{', '.join(item.get('cwe', [])) or 'N/A'}`",
                    f"- CVE: `{', '.join(item.get('cve', [])) or item.get('cve_note', '')}`",
                    f"- Why risky: {item.get('why_risky', '')}",
                    f"- Impact: {item.get('impact', '')}",
                    f"- Recommended fix: {item.get('recommended_fix', '')}",
                    "- Affected:",
                ]
            )
            for affected in item.get("affected", [])[:25]:
                lines.append(f"  - `{affected}`")
            lines.append("- Next actions:")
            for action in item.get("next_actions", [])[:10]:
                lines.append(f"  - {action}")
            lines.append("")
        return lines

    def _render_enrichment_sections(self, enrichment: dict[str, Any]) -> list[str]:
        lines: list[str] = []
        for title, key in [
            ("Path Evidence", "path_evidence"),
            ("CWE/CVE Mapping", "cwe_cve_mapping"),
            ("SOC/SIEM Exposure", "soc_siem_exposure"),
            ("Port and Service Intelligence", "port_service_intelligence"),
            ("Subdomains and Web Pages", "subdomains_and_web_pages"),
            ("Authentication Detection", "authentication_detection"),
            ("Traceroute / Hop Analysis", "traceroute_hop_analysis"),
        ]:
            lines.extend(["", f"## {title}", ""])
            lines.extend(self._render_value(enrichment.get(key, [])))
        return lines

    def _render_value(self, value: Any, depth: int = 0) -> list[str]:
        indent = "  " * depth
        if isinstance(value, dict):
            rows: list[str] = []
            for key, item in value.items():
                if item in (None, "", [], {}):
                    continue
                if isinstance(item, (dict, list)):
                    rows.append(f"{indent}- **{key}**:")
                    rows.extend(self._render_value(item, depth + 1))
                else:
                    rows.append(f"{indent}- **{key}**: `{str(item)[:500]}`")
            return rows or [f"{indent}- No findings"]
        if isinstance(value, list):
            return [f"{indent}- `{str(item)[:500]}`" for item in value[:100]] or [
                f"{indent}- No findings"
            ]
        return [f"{indent}- `{value}`"]

"""
WebOSINT Pro - JSON Report Generator
"""

import json
from datetime import datetime

from reporting.base import BaseReport
from reporting.enrichment import enrich_results


class JSONReport(BaseReport):
    extension = "json"
    format_name = "JSON"

    def save(self, path: str):
        report = {
            "tool": "WebOSINT Pro",
            "version": "1.0.0",
            "generated": datetime.now().isoformat(),
            "meta": self.results.get("meta", {}),
            "summary": self.results.get("summary", {}),
            "infrastructure": self.results.get("infrastructure", {}),
            "findings": self.results.get("findings", {}),
            "enrichment": enrich_results(self.results),
            "errors": self.results.get("errors", {}),
        }

        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str, ensure_ascii=False)

        return path

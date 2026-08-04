"""
WebOSINT Pro - Nuclei Integration
Runs nuclei templates against target for automated vuln detection.
"""

import json
import os
import shutil
from pathlib import Path

from core.safe_exec import SafeRunner

TEMPLATE_SETS = {
    "safe": ["technologies", "exposures/configs", "miscellaneous"],
    "medium": ["technologies", "exposures", "miscellaneous", "vulnerabilities/generic"],
    "aggressive": [
        "cves",
        "vulnerabilities",
        "exposures",
        "technologies",
        "miscellaneous",
        "takeovers",
        "default-logins",
    ],
    "stealth": ["technologies", "exposures/configs"],
}


class NucleiIntegration:
    def __init__(self, config, logger):
        self.runner = SafeRunner(safety=getattr(self, "safety", None))
        self.cfg = config
        self.logger = logger

    def run(self):
        if not shutil.which("nuclei"):
            return {
                "error": "nuclei not installed",
                "install": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            }

        results = {"findings": [], "total": 0}
        templates = TEMPLATE_SETS.get(self.cfg.profile, TEMPLATE_SETS["medium"])
        out_file = self.cfg.get_temp_file(".nuclei.jsonl")

        # Build command
        cmd = [
            "nuclei",
            "-u",
            f"https://{self.cfg.target}",
            "-jsonl",
            "-o",
            out_file,
            "-silent",
            "-no-color",
            "-rate-limit",
            str(min(self.cfg.rate_limit, 100)),
            "-timeout",
            str(self.cfg.timeout),
            "-retries",
            str(self.cfg.retries),
        ]

        # Add template tags
        for tag in templates[:4]:
            cmd.extend(["-tags", tag])

        if self.cfg.stealth:
            cmd.extend(["-delay", f"{int(self.cfg.delay)}s"])

        self.logger.info(f"[nuclei] Running with tags: {templates}")

        try:
            self.runner.run(cmd, timeout=300)

            if os.path.exists(out_file):
                with open(out_file) as f:
                    for line in f:
                        try:
                            finding = json.loads(line.strip())
                            results["findings"].append(
                                {
                                    "template": finding.get("template-id", ""),
                                    "name": finding.get("info", {}).get("name", ""),
                                    "severity": finding.get("info", {}).get("severity", ""),
                                    "matched": finding.get("matched-at", ""),
                                    "description": finding.get("info", {}).get("description", "")[
                                        :200
                                    ],
                                    "tags": finding.get("info", {}).get("tags", []),
                                    "cve": finding.get("info", {})
                                    .get("classification", {})
                                    .get("cve-id", []),
                                }
                            )
                        except Exception:
                            pass

            results["total"] = len(results["findings"])
            self.logger.info(f"[nuclei] Found {results['total']} issues")

        except OSError:
            results["error"] = "nuclei scan timed out (300s)"
        except Exception as e:
            results["error"] = str(e)
        finally:
            Path(out_file).unlink(missing_ok=True)

        return results

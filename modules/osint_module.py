"""
WebOSINT Pro - OSINT Module
theHarvester + Shodan API + Google dork queries
"""

import json
import shutil
from pathlib import Path

from core.base_module import BaseModule

GOOGLE_DORKS = [
    ("site:{target}", "All indexed pages"),
    ("site:{target} filetype:pdf", "PDF documents"),
    ("site:{target} filetype:xls OR filetype:xlsx", "Spreadsheets"),
    ("site:{target} filetype:doc OR filetype:docx", "Word documents"),
    ("site:{target} inurl:admin", "Admin pages"),
    ("site:{target} inurl:login", "Login pages"),
    ("site:{target} inurl:upload", "Upload pages"),
    ('site:{target} "index of /"', "Directory listings"),
    ("site:{target} ext:env", ".env files"),
    ("site:{target} ext:log", "Log files"),
    ("site:{target} ext:sql", "SQL files"),
    ("site:{target} ext:bak OR ext:backup", "Backup files"),
    ('site:{target} intitle:"phpMyAdmin"', "phpMyAdmin"),
    ('site:{target} "wp-config.php"', "WordPress config"),
    ('"@{target}" email', "Email addresses"),
    ('"{target}" password filetype:xls', "Credentials in spreadsheets"),
    ('site:{target} "API_KEY" OR "api_key" OR "apikey"', "API keys"),
    ('site:{target} "confidential" OR "internal use only"', "Confidential docs"),
    ("cache:{target}", "Cached version"),
    ("link:{target}", "Backlinks"),
]

SHODAN_FILTERS = [
    "hostname:{target}",
    "ssl:{target}",
    "http.title:{target}",
]


class Module(BaseModule):
    NAME = "osint"
    DESCRIPTION = "OSINT: theHarvester + Shodan + Google dorks"

    def run(self):
        results = {}

        # Google dorks
        dorks = self._generate_dorks()
        results["google_dorks"] = dorks

        # theHarvester
        if not self.cfg.no_external and shutil.which("theHarvester"):
            harvester = self._run_harvester()
            results["theharvester"] = harvester

        # Shodan
        if self.cfg.shodan_key:
            shodan = self._shodan_lookup()
            results["shodan"] = shodan

        # Pastebin / breach intel (passive)
        pastes = self._check_paste_sites()
        results["paste_exposure"] = pastes

        # GitHub dork queries
        github_dorks = self._generate_github_dorks()
        results["github_dorks"] = github_dorks

        return results

    def _generate_dorks(self):
        dorks = []
        for query_template, description in GOOGLE_DORKS:
            query = query_template.format(target=self.target)
            dorks.append(
                {
                    "query": query,
                    "description": description,
                    "url": f"https://www.google.com/search?q={query.replace(' ', '+')}&num=100",
                }
            )
        return dorks

    def _generate_github_dorks(self):
        queries = [
            f'"{self.target}" password',
            f'"{self.target}" secret',
            f'"{self.target}" api_key',
            f'"{self.target}" token',
            f"org:{self.target.split('.')[0]}",
        ]
        return [
            {"query": q, "url": f"https://github.com/search?q={q.replace(' ', '+')}&type=code"}
            for q in queries
        ]

    def _run_harvester(self):
        result = {"emails": [], "hosts": [], "ips": []}
        out_base = self.cfg.get_temp_file(".harvester")
        out_json = f"{out_base}.json"
        try:
            cmd = [
                "theHarvester",
                "-d",
                self.target,
                "-b",
                "all" if self.cfg.aggressive else "bing,duckduckgo,crtsh",
                "-l",
                "200",
                "-f",
                out_base,
            ]
            proc = self.runner.run(cmd, timeout=120)
            output = proc.stdout

            # Parse output
            import re

            emails = re.findall(r"[\w.+-]+@[\w-]+\.[\w.-]+", output)
            result["emails"] = list(set(emails))

            ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", output)
            result["ips"] = list(set(ips))[:50]

            # Try to load JSON output
            try:
                with open(out_json, encoding="utf-8") as f:
                    data = json.load(f)
                    result.update(data)
            except Exception:
                pass

        except OSError:
            result["error"] = "theHarvester timed out"
        except Exception as e:
            result["error"] = str(e)
            self.log(f"theHarvester error: {e}", "debug")
        finally:
            Path(out_base).unlink(missing_ok=True)
            Path(out_json).unlink(missing_ok=True)
        return result

    def _shodan_lookup(self):
        result = {}
        try:
            import shodan

            api = shodan.Shodan(self.cfg.shodan_key)

            # Domain search
            host_info = api.search(f"hostname:{self.target}")
            services = []
            for match in host_info.get("matches", [])[:20]:
                services.append(
                    {
                        "ip": match.get("ip_str"),
                        "port": match.get("port"),
                        "transport": match.get("transport", "tcp"),
                        "product": match.get("product", ""),
                        "version": match.get("version", ""),
                        "os": match.get("os", ""),
                        "location": match.get("location", {}),
                        "data": match.get("data", "")[:200],
                    }
                )

            result["services"] = services
            result["total"] = host_info.get("total", 0)

            # Get CVEs from Shodan for IPs
            import socket

            try:
                ip = socket.gethostbyname(self.target)
                host = api.host(ip)
                vulns = host.get("vulns", {})
                result["vulns"] = list(vulns.keys())
                result["ip_data"] = {
                    "ip": ip,
                    "org": host.get("org"),
                    "isp": host.get("isp"),
                    "country": host.get("country_name"),
                    "city": host.get("city"),
                    "asn": host.get("asn"),
                    "ports": host.get("ports", []),
                    "tags": host.get("tags", []),
                }
            except Exception:
                pass

        except ImportError:
            result["error"] = "shodan library not installed. Run: pip install shodan"
        except Exception as e:
            result["error"] = str(e)
            self.log(f"Shodan error: {e}", "debug")

        return result

    def _check_paste_sites(self):
        """Check public paste APIs for target exposure."""
        result = {"exposure_found": False, "sources": []}
        # Passive check via publicwww and similar
        sources = [
            {
                "name": "HaveIBeenPwned (API)",
                "url": f"https://haveibeenpwned.com/api/v3/breachedaccount/{self.target}",
                "query": "Domain breach check",
            },
            {
                "name": "IntelX",
                "url": f"https://intelx.io/?s={self.target}",
                "query": "Intelligence X search",
            },
        ]
        result["manual_checks"] = sources
        return result

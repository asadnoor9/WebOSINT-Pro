"""
WebOSINT Pro - Shodan Integration
Host lookup, service enumeration, CVE data from Shodan.
"""

import socket


class ShodanIntegration:
    def __init__(self, config, logger):
        self.cfg = config
        self.logger = logger
        self._api = None

    def _get_api(self):
        if self._api:
            return self._api
        try:
            import shodan

            self._api = shodan.Shodan(self.cfg.shodan_key)
            return self._api
        except ImportError as exc:
            raise RuntimeError("shodan library not installed. Run: pip install shodan") from exc

    def host_lookup(self, ip):
        api = self._get_api()
        try:
            return api.host(ip)
        except Exception as e:
            self.logger.debug(f"[shodan] host lookup error: {e}")
            return {}

    def domain_search(self, domain):
        api = self._get_api()
        try:
            results = api.search(f"hostname:{domain}")
            return results.get("matches", [])
        except Exception as e:
            self.logger.debug(f"[shodan] domain search error: {e}")
            return []

    def run(self):
        if not self.cfg.shodan_key:
            return {"error": "No Shodan API key configured (--shodan-key)"}

        results = {}
        target = self.cfg.target

        # Resolve to IP
        try:
            ip = socket.gethostbyname(target)
        except Exception:
            return {"error": f"Could not resolve {target}"}

        # Host data
        host_data = self.host_lookup(ip)
        if host_data:
            results["ip"] = ip
            results["org"] = host_data.get("org", "")
            results["isp"] = host_data.get("isp", "")
            results["country"] = host_data.get("country_name", "")
            results["city"] = host_data.get("city", "")
            results["asn"] = host_data.get("asn", "")
            results["os"] = host_data.get("os", "")
            results["ports"] = host_data.get("ports", [])
            results["tags"] = host_data.get("tags", [])
            results["last_update"] = host_data.get("last_update", "")

            # Vulnerabilities reported by Shodan
            vulns = host_data.get("vulns", {})
            results["vulnerabilities"] = []
            for cve_id, vuln_data in list(vulns.items())[:20]:
                results["vulnerabilities"].append(
                    {
                        "cve": cve_id,
                        "cvss": vuln_data.get("cvss", "N/A"),
                        "summary": vuln_data.get("summary", "")[:200],
                    }
                )

            # Services
            services = []
            for item in host_data.get("data", [])[:20]:
                services.append(
                    {
                        "port": item.get("port"),
                        "transport": item.get("transport", "tcp"),
                        "product": item.get("product", ""),
                        "version": item.get("version", ""),
                        "cpe": item.get("cpe", []),
                        "banner": item.get("data", "")[:200],
                    }
                )
            results["services"] = services

        # Domain search for additional hosts
        domain_matches = self.domain_search(target)
        if domain_matches:
            results["related_hosts"] = [
                {
                    "ip": m.get("ip_str"),
                    "port": m.get("port"),
                    "product": m.get("product", ""),
                    "location": m.get("location", {}),
                }
                for m in domain_matches[:10]
            ]

        return results

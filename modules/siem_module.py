"""
WebOSINT Pro - SIEM Detection Module
Exposed dashboards: Kibana, Splunk, Grafana, Graylog, ELK
"""

import time

from core.base_module import BaseModule

SIEM_TARGETS = [
    {
        "name": "Kibana",
        "ports": [5601],
        "paths": ["/", "/app/kibana", "/app/home"],
        "signatures": ["kibana", "elastic", "Discover", "dashboards"],
    },
    {
        "name": "OpenSearch Dashboards",
        "ports": [5601],
        "paths": ["/", "/app/home", "/api/status"],
        "signatures": ["opensearch dashboards", "opensearch", "security analytics"],
    },
    {
        "name": "Grafana",
        "ports": [3000],
        "paths": ["/", "/login"],
        "signatures": ["grafana", "Grafana", "grafana-app"],
    },
    {
        "name": "Splunk",
        "ports": [8000, 8089],
        "paths": ["/", "/en-US/account/login"],
        "signatures": ["splunk", "Splunk", "splunkd"],
    },
    {
        "name": "Wazuh",
        "ports": [443, 5601, 8200, 55000, 1514, 1515],
        "paths": ["/", "/app/wazuh", "/api", "/security"],
        "signatures": ["wazuh", "wazuh api", "wazuh dashboard"],
    },
    {
        "name": "Graylog",
        "ports": [9000],
        "paths": ["/", "/api"],
        "signatures": ["graylog", "Graylog"],
    },
    {
        "name": "Elasticsearch",
        "ports": [9200, 9300],
        "paths": ["/", "/_cluster/health", "/_cat/indices"],
        "signatures": ["elasticsearch", "cluster_name", "tagline", "you know, for search"],
    },
    {
        "name": "Microsoft Sentinel",
        "ports": [80, 443],
        "paths": ["/", "/signin-oidc", "/oauth2", "/saml"],
        "signatures": ["microsoft sentinel", "azure sentinel", "log analytics", "microsoftonline"],
    },
    {
        "name": "QRadar",
        "ports": [443, 514, 1514],
        "paths": ["/", "/console", "/api"],
        "signatures": ["qradar", "ibm security"],
    },
    {
        "name": "Security Onion",
        "ports": [443, 5601, 8080],
        "paths": ["/", "/app/dashboards", "/login"],
        "signatures": ["security onion", "soc login", "squert", "so-grid"],
    },
    {
        "name": "Prometheus",
        "ports": [9090],
        "paths": ["/", "/graph", "/metrics"],
        "signatures": ["prometheus", "Prometheus", "tsdb"],
    },
    {"name": "Jaeger", "ports": [16686], "paths": ["/"], "signatures": ["jaeger", "Jaeger UI"]},
    {"name": "Zipkin", "ports": [9411], "paths": ["/"], "signatures": ["zipkin", "Zipkin"]},
    {
        "name": "Chronograf",
        "ports": [8888],
        "paths": ["/"],
        "signatures": ["chronograf", "Chronograf"],
    },
    {
        "name": "Logstash Beats",
        "ports": [5044, 514, 1514],
        "paths": ["/"],
        "signatures": ["logstash", "beats", "elastic"],
    },
]


class Module(BaseModule):
    NAME = "siem"
    DESCRIPTION = "SIEM/logging dashboard detection: Kibana, Splunk, Grafana"

    # Wall-clock ceiling for the whole sweep, in seconds.
    BUDGET_SECONDS = 240

    def run(self):
        results = {"detected": [], "checks": []}
        seen = set()

        # Probing every SIEM port/path over both schemes stalls badly when a
        # firewall blackholes the traffic, so the sweep gets a hard wall-clock
        # budget and gives up cleanly instead of hanging the whole scan.
        budget = float(getattr(self.cfg, "module_budget_seconds", 0) or self.BUDGET_SECONDS)
        deadline = time.monotonic() + budget
        probe_timeout = max(1, min(5, int(self.timeout)))

        for tool in SIEM_TARGETS:
            if time.monotonic() > deadline:
                results["budget_exhausted"] = True
                self.log(f"SIEM sweep stopped after its {budget:.0f}s budget", "debug")
                break
            for port in tool["ports"]:
                for scheme in ["http", "https"]:
                    for path in tool["paths"]:
                        if time.monotonic() > deadline:
                            results["budget_exhausted"] = True
                            break
                        url = f"{scheme}://{self.target}:{port}{path}"
                        try:
                            r = self.session.get(url, timeout=probe_timeout, allow_redirects=True)
                            if r and r.status_code in (200, 302, 401, 403):
                                body_lower = r.text.lower()
                                headers_lower = str(dict(r.headers)).lower()
                                for sig in tool["signatures"]:
                                    if sig.lower() in body_lower or sig.lower() in headers_lower:
                                        auth_required = self._auth_required(r)
                                        accessible = r.status_code == 200 and not auth_required
                                        entry = {
                                            "name": tool["name"],
                                            "service_name": tool["name"],
                                            "likely_product": tool["name"],
                                            "url": url,
                                            "port": port,
                                            "scheme": scheme,
                                            "status": r.status_code,
                                            "status_code": r.status_code,
                                            "accessible": accessible,
                                            "auth_required": auth_required,
                                            "auth_requirement": "required"
                                            if auth_required
                                            else "not-observed",
                                            "banner": self._banner(r),
                                            "fingerprint": sig,
                                            "confidence": "high"
                                            if sig.lower() in body_lower
                                            else "medium",
                                            "content_type": r.headers.get("content-type", ""),
                                            "response_size": len(r.content),
                                            "exposure_risk": "critical" if accessible else "high",
                                            "suggested_remediation": (
                                                "Restrict SOC/SIEM portals to VPN/private networks, "
                                                "enforce SSO/MFA, and block direct internet access."
                                            ),
                                            "cwe": ["CWE-200", "CWE-284", "CWE-552"],
                                        }
                                        marker = (entry["name"], entry["url"], entry["status_code"])
                                        if marker not in seen:
                                            seen.add(marker)
                                            results["detected"].append(entry)
                                        break
                        except Exception as exc:
                            self.log(f"SIEM check failed for {url}: {exc}", "debug")

        if results["detected"]:
            any_open = any(d["accessible"] for d in results["detected"])
            results["_risk_siem_exposed"] = "critical" if any_open else "high"

        return results

    def _auth_required(self, response):
        if response.status_code in (401, 403):
            return True
        location = response.headers.get("location", "").lower()
        body = response.text[:5000].lower()
        return any(
            token in location or token in body
            for token in ["login", "signin", "saml", "oauth", "microsoftonline", "auth"]
        )

    def _banner(self, response):
        server = response.headers.get("server", "")
        powered = response.headers.get("x-powered-by", "")
        title = ""
        import re

        match = re.search(r"<title[^>]*>([^<]+)</title>", response.text, re.I)
        if match:
            title = match.group(1).strip()[:120]
        return " | ".join(part for part in [server, powered, title] if part)

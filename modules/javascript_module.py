"""
WebOSINT Pro - JavaScript Analysis Module
Extract endpoints, secrets (API keys, tokens), JS file mapping
"""

import re
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.base_module import BaseModule

SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r'(?i)aws.{0,20}secret.{0,20}["\']([A-Za-z0-9/+=]{40})',
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Google OAuth": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
    "Firebase": r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
    "Stripe API Key": r"sk_live_[0-9a-zA-Z]{24}",
    "Stripe Restricted Key": r"rk_live_[0-9a-zA-Z]{24}",
    "Stripe Publishable": r"pk_live_[0-9a-zA-Z]{24}",
    "GitHub Token": r"ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9]{82}",
    "GitLab Token": r"glpat-[A-Za-z0-9\-_]{20}",
    "Slack Token": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
    "Slack Webhook": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9]+/B[a-zA-Z0-9]+",
    "Twilio SID": r"AC[a-z0-9]{32}",
    "Twilio Token": r"SK[a-z0-9]{32}",
    "SendGrid Key": r"SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}",
    "Mailgun Key": r"key-[0-9a-zA-Z]{32}",
    "JWT Token": r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]+",
    "Private Key": r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
    "Password in URL": r'["\']password["\']\s*[:=]\s*["\']([^"\']{4,})["\']',
    "Secret in Code": r'(?i)(?:secret|password|passwd|api_key|apikey|token)\s*[=:]\s*["\']([^"\']{8,})["\']',
    "Bearer Token": r"[Bb]earer\s+([A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)",
    "Basic Auth in URL": r"https?://[^:]+:[^@]+@",
    "Internal IP": r"(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}",
    "Heroku API Key": r"[h|H][e|E][r|R][o|O][k|K][u|U].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}",
}

ENDPOINT_PATTERN = re.compile(
    r'(?:url|path|endpoint|href|src|action|redirect)\s*[:=]\s*["\']([/][^"\'<>\s]{2,})["\']'
    r'|fetch\(["\']([/][^"\'<>\s]{2,})["\']'
    r'|axios\.(?:get|post|put|delete|patch)\(["\']([^"\'<>\s]{4,})["\']',
    re.I,
)

JS_FILE_PATTERN = re.compile(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', re.I)


class Module(BaseModule):
    NAME = "javascript"
    DESCRIPTION = "JS analysis: endpoint extraction, secret detection"

    def run(self):
        results = {
            "js_files": [],
            "endpoints": [],
            "secrets": [],
            "inline_secrets": [],
        }

        base_url = f"https://{self.target}"
        r = self.get(base_url)
        if not r:
            return results

        # Extract JS file URLs
        js_urls = self._extract_js_urls(r.text, base_url)
        results["js_files"] = js_urls
        self.log(f"Found {len(js_urls)} JS files")

        # Scan inline scripts
        inline_secrets = self._scan_inline_scripts(r.text)
        results["inline_secrets"] = inline_secrets

        # Fetch & analyze JS files in parallel
        all_endpoints = set()
        all_secrets = []

        def analyze_js(url):
            js_r = self.get(url)
            if not js_r or js_r.status_code != 200:
                return [], []
            content = js_r.text
            eps = self._extract_endpoints(content)
            secs = self._detect_secrets(content, url)
            return eps, secs

        max_js = 20 if self.cfg.aggressive else 10
        with ThreadPoolExecutor(max_workers=self.cfg.threads) as ex:
            futures = {ex.submit(analyze_js, url): url for url in js_urls[:max_js]}
            for f in as_completed(futures):
                eps, secs = f.result()
                all_endpoints.update(eps)
                all_secrets.extend(secs)

        results["endpoints"] = sorted(list(all_endpoints))
        results["secrets"] = all_secrets

        if all_secrets or inline_secrets:
            results["_risk_secrets"] = "critical"

        return results

    def _extract_js_urls(self, html, base_url):
        urls = []
        for match in JS_FILE_PATTERN.finditer(html):
            src = match.group(1)
            if src.startswith("//"):
                src = "https:" + src
            elif src.startswith("/"):
                src = base_url.rstrip("/") + src
            elif not src.startswith("http"):
                src = base_url.rstrip("/") + "/" + src
            if self.target in src or src.startswith("/"):
                urls.append(src)
        return list(set(urls))

    def _extract_endpoints(self, content):
        endpoints = set()
        for match in ENDPOINT_PATTERN.finditer(content):
            for grp in match.groups():
                if grp and len(grp) > 2:
                    endpoints.add(grp)
        # Also find paths like "/api/v1/users"
        path_matches = re.findall(
            r'["\`](/(?:api|v\d|rest|graphql|admin)[^"\'<>\s`]{1,100})', content
        )
        endpoints.update(path_matches)
        return endpoints

    def _detect_secrets(self, content, source_url):
        found = []
        for name, pattern in SECRET_PATTERNS.items():
            matches = re.findall(pattern, content)
            if matches:
                for match in matches[:3]:  # cap per type
                    value = match if isinstance(match, str) else match[0] if match else ""
                    if len(value) > 3:
                        found.append(
                            {
                                "type": name,
                                "value": value[:50] + "..." if len(value) > 50 else value,
                                "source": source_url,
                            }
                        )
        return found

    def _scan_inline_scripts(self, html):
        found = []
        inline = re.findall(r"<script[^>]*>(.*?)</script>", html, re.DOTALL | re.I)
        for script in inline:
            for name, pattern in SECRET_PATTERNS.items():
                matches = re.findall(pattern, script)
                if matches:
                    for match in matches[:2]:
                        value = match if isinstance(match, str) else match[0] if match else ""
                        if len(value) > 3:
                            found.append({"type": name, "value": value[:50], "source": "inline"})
        return found

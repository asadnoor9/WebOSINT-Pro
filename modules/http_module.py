"""
WebOSINT Pro - HTTP Module
Headers, security headers, server detection, CDN, tech fingerprinting
"""

from core.base_module import BaseModule

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "x-xss-protection",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-embedder-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
]

CDN_SIGNATURES = {
    "Cloudflare": ["cf-ray", "cf-cache-status", "server:cloudflare"],
    "AWS CloudFront": ["x-amz-cf-id", "x-amz-cf-pop", "x-cache:cloudfront"],
    "Fastly": ["x-served-by", "x-cache-hits", "fastly"],
    "Akamai": ["x-check-cacheable", "akamai", "x-akamai"],
    "Varnish": ["x-varnish", "via:varnish"],
    "Nginx": ["server:nginx"],
    "Apache": ["server:apache"],
    "IIS": ["server:iis", "x-powered-by:asp.net"],
    "LiteSpeed": ["server:litespeed"],
    "Caddy": ["server:caddy"],
    "BunnyCDN": ["bunnycdn", "cdn-pullzone"],
    "KeyCDN": ["x-edge-location", "keycdn"],
    "Azure CDN": ["x-ec-custom-error", "x-ms-request-id"],
}

SERVER_PATTERNS = {
    "nginx": "Nginx",
    "apache": "Apache",
    "iis": "Microsoft IIS",
    "litespeed": "LiteSpeed",
    "caddy": "Caddy",
    "gunicorn": "Gunicorn",
    "uvicorn": "Uvicorn",
    "openresty": "OpenResty",
    "cloudflare": "Cloudflare",
    "express": "Express.js",
    "node.js": "Node.js",
    "tomcat": "Apache Tomcat",
    "jetty": "Jetty",
}

INTERESTING_HEADERS = [
    "x-powered-by",
    "x-generator",
    "x-drupal-cache",
    "x-wordpress",
    "x-aspnet-version",
    "x-runtime",
    "x-rails-cache",
]


class Module(BaseModule):
    NAME = "http"
    DESCRIPTION = "HTTP headers, security analysis, server/CDN detection"

    def run(self):
        results = {}

        for scheme in ["https", "http"]:
            url = f"{scheme}://{self.target}"
            r = self.get(url, allow_redirects=True)
            if r:
                results["base_url"] = url
                results["status_code"] = r.status_code
                results["final_url"] = r.url
                results["redirect_chain"] = [str(resp.url) for resp in r.history]

                headers = {k.lower(): v for k, v in r.headers.items()}
                results["headers"] = dict(r.headers)

                # Security headers analysis
                results["security_headers"] = self._check_security_headers(headers)

                # Missing security headers
                missing = [h for h in SECURITY_HEADERS if h not in headers]
                results["missing_security_headers"] = missing
                if missing:
                    results["_risk_missing_headers"] = "medium"

                # Server detection
                server = self._detect_server(headers)
                results["server"] = server

                # CDN detection
                cdn = self._detect_cdn(headers, r.text)
                results["cdn"] = cdn

                # Interesting headers (info leakage)
                interesting = {}
                for h in INTERESTING_HEADERS:
                    if h in headers:
                        interesting[h] = headers[h]
                results["info_disclosure_headers"] = interesting
                if interesting:
                    results["_risk_header_disclosure"] = "low"

                # Cookie security
                cookies = self._analyze_cookies(r)
                results["cookies"] = cookies

                # HSTS
                hsts = headers.get("strict-transport-security", "")
                results["hsts"] = {"present": bool(hsts), "value": hsts}

                # HTTP methods allowed
                methods = self._check_methods(url)
                results["allowed_methods"] = methods
                if "TRACE" in methods or "PUT" in methods or "DELETE" in methods:
                    results["_risk_dangerous_methods"] = "medium"

                break

        return results

    def _check_security_headers(self, headers):
        present = {}
        for h in SECURITY_HEADERS:
            if h in headers:
                present[h] = headers[h]
        return present

    def _detect_server(self, headers):
        server_header = headers.get("server", "").lower()
        powered = headers.get("x-powered-by", "").lower()
        combined = f"{server_header} {powered}"

        for pattern, name in SERVER_PATTERNS.items():
            if pattern in combined:
                return name
        return server_header or "Unknown"

    def _detect_cdn(self, headers, body=""):
        detected = []
        combined = " ".join(f"{k}:{v}" for k, v in headers.items()).lower()
        body_lower = (body or "").lower()[:5000]

        for cdn, sigs in CDN_SIGNATURES.items():
            for sig in sigs:
                if ":" in sig:
                    k, v = sig.split(":", 1)
                    if k in headers and v.lower() in headers[k].lower():
                        detected.append(cdn)
                        break
                elif sig in combined or sig in body_lower:
                    detected.append(cdn)
                    break

        return list(set(detected))

    def _analyze_cookies(self, response):
        cookies_info = []
        for cookie in response.cookies:
            info = {
                "name": cookie.name,
                "secure": cookie.secure,
                "httponly": "httponly" in str(cookie.__dict__).lower(),
                "samesite": cookie.__dict__.get("_rest", {}).get("SameSite", "Not set"),
                "domain": cookie.domain,
                "path": cookie.path,
            }
            risks = []
            if not cookie.secure:
                risks.append("no-secure-flag")
            if not info["httponly"]:
                risks.append("no-httponly-flag")
            if info["samesite"] == "Not set":
                risks.append("no-samesite")
            info["risks"] = risks
            cookies_info.append(info)
        return cookies_info

    def _check_methods(self, url):
        try:
            r = self.session.options(url, timeout=self.timeout)
            allowed = r.headers.get("Allow", r.headers.get("allow", ""))
            if allowed:
                return [m.strip() for m in allowed.split(",")]
        except Exception:
            pass
        return []

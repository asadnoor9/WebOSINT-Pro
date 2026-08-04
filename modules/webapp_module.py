"""
WebOSINT Pro - Web App Structure Module
Robots.txt, sitemap, tech stack fingerprinting
"""

import re
import xml.etree.ElementTree as ET
from urllib.parse import urljoin, urlparse

from core.base_module import BaseModule

TECH_SIGNATURES = {
    "WordPress": ["wp-content", "wp-includes", "WordPress"],
    "Joomla": ["joomla", "/components/com_"],
    "Drupal": ["drupal", "/sites/default/", "Drupal.settings"],
    "Magento": ["Mage.Cookies", "magento", "/skin/frontend/"],
    "Shopify": ["shopify", "cdn.shopify.com", "myshopify.com"],
    "PrestaShop": ["prestashop", "/modules/"],
    "Django": ["csrfmiddlewaretoken", "django"],
    "Rails": ["rails", "csrf-token", "_rails-"],
    "Laravel": ["laravel_session", "XSRF-TOKEN"],
    "Angular": ["ng-version", "angular", "__ng_"],
    "React": ["_react", "__REACT", "data-reactroot"],
    "Vue.js": ["__vue", "data-v-", "vue.js"],
    "Next.js": ["__NEXT_DATA__", "_next/"],
    "Nuxt.js": ["__NUXT__", "_nuxt/"],
    "jQuery": ["jquery", "jQuery"],
    "Bootstrap": ["bootstrap"],
    "Tailwind": ["tailwind"],
}


class Module(BaseModule):
    NAME = "webapp"
    DESCRIPTION = "Robots.txt, sitemap, tech fingerprinting"

    def run(self):
        results = {}
        base = f"https://{self.target}"

        # Robots.txt
        robots = self._parse_robots(base)
        results["robots_txt"] = robots

        # Sitemap
        sitemap_urls = robots.get("sitemaps", [])
        if not sitemap_urls:
            sitemap_urls = [f"{base}/sitemap.xml", f"{base}/sitemap_index.xml"]

        sitemap_data = self._parse_sitemaps(sitemap_urls)
        results["sitemap"] = sitemap_data

        # Tech fingerprint from homepage
        tech = self._fingerprint_tech(base)
        results["technologies"] = tech

        # Meta info
        meta = self._extract_meta(base)
        results["meta"] = meta
        results["pages"] = self._discover_pages(base, robots, sitemap_data)

        # Favicon hash (useful for Shodan searches)
        favicon = self._get_favicon_hash(base)
        results["favicon"] = favicon

        return results

    def _discover_pages(self, base, robots, sitemap_data):
        candidates = {base, f"{base}/login", f"{base}/admin", f"{base}/dashboard"}
        for item in robots.get("disallowed", [])[:25]:
            path = item.get("path", "")
            if path.startswith("/"):
                candidates.add(urljoin(base, path))
        for url in sitemap_data.get("urls", [])[:50]:
            if self.target in url:
                candidates.add(url)

        pages = []
        seen = set()
        for url in sorted(candidates)[:75]:
            try:
                r = self.get(url, allow_redirects=True)
                if not r or r.status_code >= 500:
                    continue
                parsed = urlparse(str(r.url))
                if self.target not in parsed.netloc:
                    continue
                page = {
                    "url": url,
                    "final_url": r.url,
                    "path": parsed.path or "/",
                    "status_code": r.status_code,
                    "redirected": bool(r.history),
                    "redirect_chain": [str(resp.url) for resp in r.history],
                    "title": self._title(r.text),
                    "content_type": r.headers.get("content-type", ""),
                    "response_size": len(r.content),
                    "is_login_page": self._is_login_page(r),
                    "is_admin_page": any(
                        token in parsed.path.lower() for token in ["admin", "dashboard", "console"]
                    ),
                    "forms": self._forms(r.text),
                    "auth_type": self._detect_auth_type(r),
                    "auth_indicators": self._auth_indicators(r),
                    "set_cookie_flags": self._set_cookie_flags(r),
                    "framework_hints": self._framework_hints(r),
                }
                marker = (page["final_url"], page["status_code"])
                if marker not in seen:
                    seen.add(marker)
                    pages.append(page)
            except Exception as exc:
                self.log(f"Page discovery failed for {url}: {exc}", "debug")
        return pages

    def _parse_robots(self, base):
        data = {"raw": "", "disallowed": [], "allowed": [], "sitemaps": [], "user_agents": []}
        try:
            r = self.get(f"{base}/robots.txt")
            if r and r.status_code == 200 and "text" in r.headers.get("content-type", "text"):
                data["raw"] = r.text
                current_ua = "*"
                for line in r.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith("user-agent:"):
                        current_ua = line.split(":", 1)[1].strip()
                        if current_ua not in data["user_agents"]:
                            data["user_agents"].append(current_ua)
                    elif line.lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path:
                            data["disallowed"].append({"ua": current_ua, "path": path})
                    elif line.lower().startswith("allow:"):
                        path = line.split(":", 1)[1].strip()
                        if path:
                            data["allowed"].append({"ua": current_ua, "path": path})
                    elif line.lower().startswith("sitemap:"):
                        url = line.split(":", 1)[1].strip()
                        if url:
                            data["sitemaps"].append(url)
        except Exception as e:
            self.log(f"Robots.txt error: {e}", "debug")
        return data

    def _parse_sitemaps(self, sitemap_urls):
        all_urls = []
        processed = set()

        def fetch_sitemap(url):
            if url in processed:
                return
            processed.add(url)
            try:
                r = self.get(url)
                if not r or r.status_code != 200:
                    return
                root = ET.fromstring(r.content)
                ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}

                # Sitemap index
                for sitemap in root.findall("sm:sitemap", ns):
                    loc = sitemap.find("sm:loc", ns)
                    if loc is not None and loc.text:
                        fetch_sitemap(loc.text.strip())

                # URLs
                for url_elem in root.findall("sm:url", ns):
                    loc = url_elem.find("sm:loc", ns)
                    if loc is not None and loc.text:
                        all_urls.append(loc.text.strip())
            except Exception as e:
                self.log(f"Sitemap parse error {url}: {e}", "debug")

        for url in sitemap_urls[:5]:
            fetch_sitemap(url)

        return {
            "total_urls": len(all_urls),
            "urls": all_urls[:100],  # cap
        }

    def _fingerprint_tech(self, base):
        detected = []
        try:
            r = self.get(base)
            if not r:
                return detected
            body = r.text
            headers_str = str(r.headers)

            for tech, sigs in TECH_SIGNATURES.items():
                for sig in sigs:
                    if sig in body or sig in headers_str:
                        detected.append(tech)
                        break
        except Exception as e:
            self.log(f"Tech fingerprint error: {e}", "debug")
        return list(set(detected))

    def _extract_meta(self, base):
        meta = {}
        try:
            r = self.get(base)
            if not r:
                return meta
            body = r.text

            # Generator
            gen = re.search(
                r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I
            )
            if gen:
                meta["generator"] = gen.group(1)

            # Title
            title = re.search(r"<title[^>]*>([^<]+)</title>", body, re.I)
            if title:
                meta["title"] = title.group(1).strip()

            # Description
            desc = re.search(
                r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)', body, re.I
            )
            if desc:
                meta["description"] = desc.group(1)[:200]

        except Exception as e:
            self.log(f"Meta extract error: {e}", "debug")
        return meta

    def _title(self, body):
        title = re.search(r"<title[^>]*>([^<]+)</title>", body or "", re.I)
        return title.group(1).strip()[:120] if title else ""

    def _forms(self, body):
        forms = []
        for form in re.findall(r"<form[^>]*>(.*?)</form>", body or "", re.I | re.S)[:10]:
            forms.append(
                {
                    "has_password": bool(re.search(r'type=["\']password["\']', form, re.I)),
                    "has_csrf": "csrf" in form.lower() or "_token" in form.lower(),
                    "method": self._form_attr(form, "method") or "get",
                    "action": self._form_attr(form, "action") or "",
                }
            )
        return forms

    def _form_attr(self, form, attr):
        match = re.search(rf'{attr}=["\']([^"\']+)["\']', form or "", re.I)
        return match.group(1) if match else ""

    def _is_login_page(self, response):
        body = (response.text or "")[:10000].lower()
        return "<form" in body and any(token in body for token in ["password", "login", "signin"])

    def _auth_indicators(self, response):
        body = (response.text or "")[:10000].lower()
        location = response.headers.get("location", "").lower()
        headers = str(dict(response.headers)).lower()
        indicators = []
        checks = {
            "login-form": self._is_login_page(response),
            "basic-auth": response.status_code == 401 or "www-authenticate" in response.headers,
            "redirect-login": any(token in location for token in ["login", "signin", "auth"]),
            "sso": any(
                token in body + location
                for token in ["saml", "oauth", "openid", "microsoftonline", "okta"]
            ),
            "api-token": any(token in headers for token in ["bearer", "jwt", "token"]),
            "session-cookie": bool(response.cookies),
        }
        for name, present in checks.items():
            if present:
                indicators.append(name)
        return indicators

    def _detect_auth_type(self, response):
        indicators = self._auth_indicators(response)
        if "basic-auth" in indicators:
            return "basic auth"
        if "sso" in indicators:
            return "SSO / SAML / OAuth"
        if "api-token" in indicators:
            return "token-based API auth"
        if "login-form" in indicators:
            return "form login"
        if "redirect-login" in indicators or "session-cookie" in indicators:
            return "session-based login"
        if response.status_code in (401, 403):
            return "unknown"
        return "none"

    def _set_cookie_flags(self, response):
        return [
            {
                "name": c.name,
                "secure": c.secure,
                "httponly": "httponly" in str(c.__dict__).lower(),
                "samesite": c.__dict__.get("_rest", {}).get("SameSite", "Not set"),
            }
            for c in response.cookies
        ]

    def _framework_hints(self, response):
        body = response.text or ""
        headers = str(dict(response.headers))
        hints = []
        for tech, signatures in TECH_SIGNATURES.items():
            if any(sig in body or sig in headers for sig in signatures):
                hints.append(tech)
        return sorted(set(hints))

    def _get_favicon_hash(self, base):
        import hashlib

        try:
            r = self.get(f"{base}/favicon.ico")
            if r and r.status_code == 200 and r.content:
                import base64

                import mmh3

                b64 = base64.encodebytes(r.content)
                fhash = mmh3.hash(b64)
                return {"hash": fhash, "shodan_query": f"http.favicon.hash:{fhash}"}
        except ImportError:
            try:
                r = self.get(f"{base}/favicon.ico")
                if r and r.content:
                    return {"md5": hashlib.md5(r.content).hexdigest()}
            except Exception:
                pass
        except Exception:
            pass
        return {}

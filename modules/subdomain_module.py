"""
WebOSINT Pro - Subdomain Enumeration Module
Wordlist brute force + crt.sh CT logs + subfinder + amass integration
"""

import re
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import dns.resolver

from core.base_module import BaseModule

DEFAULT_WORDLIST = [
    "www",
    "mail",
    "remote",
    "blog",
    "webmail",
    "server",
    "ns1",
    "ns2",
    "smtp",
    "secure",
    "vpn",
    "api",
    "dev",
    "staging",
    "test",
    "admin",
    "portal",
    "cdn",
    "app",
    "apps",
    "ftp",
    "ssh",
    "mx",
    "shop",
    "store",
    "support",
    "help",
    "docs",
    "wiki",
    "status",
    "monitor",
    "dashboard",
    "login",
    "auth",
    "accounts",
    "internal",
    "intranet",
    "extranet",
    "db",
    "database",
    "mysql",
    "postgres",
    "redis",
    "mongo",
    "elastic",
    "jenkins",
    "gitlab",
    "github",
    "jira",
    "confluence",
    "bitbucket",
    "cloud",
    "aws",
    "azure",
    "gcp",
    "k8s",
    "kubernetes",
    "docker",
    "ci",
    "cd",
    "build",
    "deploy",
    "prod",
    "production",
    "beta",
    "mobile",
    "api-v1",
    "api-v2",
    "graphql",
    "rest",
    "soap",
    "old",
    "new",
    "demo",
    "sandbox",
    "qa",
    "uat",
    "preview",
    "assets",
    "static",
    "media",
    "images",
    "img",
    "upload",
    "uploads",
    "backup",
    "bak",
    "archive",
    "data",
    "files",
    "download",
    "downloads",
]


class Module(BaseModule):
    NAME = "subdomains"
    DESCRIPTION = "Subdomain enumeration: brute force + CT logs + tools"

    def run(self):
        found = set()

        # 1. crt.sh certificate transparency
        ct_subs = self._crtsh()
        found.update(ct_subs)
        self.log(f"crt.sh found {len(ct_subs)} subdomains")

        # 2. Wordlist brute force (unless passive only)
        if not self.cfg.passive_only:
            words = self._load_wordlist()
            bf_subs = self._brute_force(words)
            found.update(bf_subs)
            self.log(f"Brute force found {len(bf_subs)} subdomains")

        # 3. External tool integrations
        if not self.cfg.no_external:
            if shutil.which("subfinder"):
                sf_subs = self._subfinder()
                found.update(sf_subs)
                self.log(f"subfinder found {len(sf_subs)} subdomains")

            if shutil.which("amass") and self.cfg.aggressive:
                am_subs = self._amass()
                found.update(am_subs)
                self.log(f"amass found {len(am_subs)} subdomains")

        # Validate + resolve
        resolved = self._resolve_all(list(found))
        live_hosts = self._probe_live_hosts(sorted(found))

        return {
            "total_found": len(found),
            "resolved": resolved,
            "live_hosts": live_hosts,
            "all_subdomains": sorted(list(found)),
        }

    def _crtsh(self):
        subs = set()
        try:
            r = self.get(
                f"https://crt.sh/?q=%.{self.target}&output=json",
                headers={"Accept": "application/json"},
            )
            if r and r.status_code == 200:
                entries = r.json()
                for entry in entries:
                    names = entry.get("name_value", "").split("\n")
                    for name in names:
                        name = name.strip().lstrip("*.")
                        if name.endswith(self.target) and name != self.target:
                            subs.add(name.lower())
        except Exception as e:
            self.log(f"crt.sh error: {e}", "warning")
        return subs

    def _load_wordlist(self):
        if self.cfg.wordlist:
            try:
                with open(self.cfg.wordlist) as f:
                    return [line.strip() for line in f if line.strip()]
            except Exception as e:
                self.log(f"Wordlist load error: {e}", "warning")
        return DEFAULT_WORDLIST

    def _brute_force(self, words):
        found = set()
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3

        def check(word):
            fqdn = f"{word}.{self.target}"
            try:
                resolver.resolve(fqdn, "A")
                return fqdn
            except Exception:
                try:
                    resolver.resolve(fqdn, "AAAA")
                    return fqdn
                except Exception:
                    return None

        max_workers = min(50, self.cfg.threads * 3)
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {ex.submit(check, w): w for w in words}
            for f in as_completed(futures):
                result = f.result()
                if result:
                    found.add(result)

        return found

    def _subfinder(self):
        subs = set()
        out_file = self.cfg.get_temp_file(".subfinder.txt")
        try:
            cmd = ["subfinder", "-d", self.target, "-silent", "-o", out_file]
            if self.cfg.aggressive:
                cmd.extend(["-all"])
            self.runner.run(cmd, timeout=120)
            with open(out_file, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        subs.add(line)
        except Exception as e:
            self.log(f"subfinder error: {e}", "debug")
        finally:
            Path(out_file).unlink(missing_ok=True)
        return subs

    def _amass(self):
        subs = set()
        out_file = self.cfg.get_temp_file(".amass.txt")
        try:
            cmd = ["amass", "enum", "-passive", "-d", self.target, "-o", out_file]
            if self.cfg.aggressive:
                cmd = ["amass", "enum", "-active", "-d", self.target, "-o", out_file]
            self.runner.run(cmd, timeout=300)
            with open(out_file, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        subs.add(line)
        except Exception as e:
            self.log(f"amass error: {e}", "debug")
        finally:
            Path(out_file).unlink(missing_ok=True)
        return subs

    def _resolve_all(self, subs):
        resolved = {}
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3

        def resolve_one(sub):
            try:
                ans = resolver.resolve(sub, "A")
                return sub, [str(r) for r in ans]
            except Exception:
                return sub, None

        with ThreadPoolExecutor(max_workers=self.cfg.threads) as ex:
            for sub, ips in ex.map(resolve_one, subs):
                if ips:
                    resolved[sub] = ips

        return resolved

    def _probe_live_hosts(self, subs):
        live = []
        seen = set()

        def probe(host):
            for scheme in ("https", "http"):
                url = f"{scheme}://{host}"
                try:
                    r = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                    if r.status_code < 500:
                        return {
                            "host": host,
                            "url": url,
                            "final_url": r.url,
                            "status_code": r.status_code,
                            "redirected": bool(r.history),
                            "redirect_chain": [str(resp.url) for resp in r.history],
                            "title": self._title(r.text),
                            "content_type": r.headers.get("content-type", ""),
                            "response_size": len(r.content),
                            "auth_type": self._detect_auth_type(r),
                            "auth_indicators": self._auth_indicators(r),
                            "cookies": [
                                {
                                    "name": c.name,
                                    "secure": c.secure,
                                    "httponly": "httponly" in str(c.__dict__).lower(),
                                }
                                for c in r.cookies
                            ],
                        }
                except Exception as exc:
                    self.log(f"Live host probe failed for {url}: {exc}", "debug")
            return None

        with ThreadPoolExecutor(max_workers=min(self.cfg.threads, 20)) as ex:
            futures = {ex.submit(probe, sub): sub for sub in subs[:100]}
            for future in as_completed(futures):
                result = future.result()
                if result and result["host"] not in seen:
                    seen.add(result["host"])
                    live.append(result)
        return sorted(live, key=lambda row: row["host"])

    def _title(self, body):
        match = re.search(r"<title[^>]*>([^<]+)</title>", body or "", re.I)
        return match.group(1).strip()[:120] if match else ""

    def _auth_indicators(self, response):
        body = (response.text or "")[:8000].lower()
        location = response.headers.get("location", "").lower()
        indicators = []
        checks = {
            "login-form": "<form" in body
            and any(token in body for token in ["password", "login", "signin"]),
            "basic-auth": response.status_code == 401 or "www-authenticate" in response.headers,
            "redirect-login": any(token in location for token in ["login", "signin", "auth"]),
            "sso": any(
                token in body + location
                for token in ["saml", "oauth", "openid", "microsoftonline", "okta"]
            ),
            "api-token": any(
                token in str(response.headers).lower() for token in ["bearer", "jwt", "token"]
            ),
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
        if "redirect-login" in indicators:
            return "session-based login"
        if response.status_code in (401, 403):
            return "unknown"
        return "none"

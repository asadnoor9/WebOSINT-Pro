"""
WebOSINT Pro - Subdomain Enumeration Module
Wordlist brute force + crt.sh CT logs + subfinder + amass integration
"""

import dns.resolver
import json
import subprocess
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.base_module import BaseModule


DEFAULT_WORDLIST = [
    'www', 'mail', 'remote', 'blog', 'webmail', 'server', 'ns1', 'ns2',
    'smtp', 'secure', 'vpn', 'api', 'dev', 'staging', 'test', 'admin',
    'portal', 'cdn', 'app', 'apps', 'ftp', 'ssh', 'mx', 'shop', 'store',
    'support', 'help', 'docs', 'wiki', 'status', 'monitor', 'dashboard',
    'login', 'auth', 'accounts', 'internal', 'intranet', 'extranet',
    'db', 'database', 'mysql', 'postgres', 'redis', 'mongo', 'elastic',
    'jenkins', 'gitlab', 'github', 'jira', 'confluence', 'bitbucket',
    'cloud', 'aws', 'azure', 'gcp', 'k8s', 'kubernetes', 'docker',
    'ci', 'cd', 'build', 'deploy', 'prod', 'production', 'beta',
    'mobile', 'api-v1', 'api-v2', 'graphql', 'rest', 'soap',
    'old', 'new', 'demo', 'sandbox', 'qa', 'uat', 'preview',
    'assets', 'static', 'media', 'images', 'img', 'upload', 'uploads',
    'backup', 'bak', 'archive', 'data', 'files', 'download', 'downloads',
]


class Module(BaseModule):
    NAME = 'subdomains'
    DESCRIPTION = 'Subdomain enumeration: brute force + CT logs + tools'

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
            if shutil.which('subfinder'):
                sf_subs = self._subfinder()
                found.update(sf_subs)
                self.log(f"subfinder found {len(sf_subs)} subdomains")

            if shutil.which('amass') and self.cfg.aggressive:
                am_subs = self._amass()
                found.update(am_subs)
                self.log(f"amass found {len(am_subs)} subdomains")

        # Validate + resolve
        resolved = self._resolve_all(list(found))

        return {
            'total_found': len(found),
            'resolved': resolved,
            'all_subdomains': sorted(list(found)),
        }

    def _crtsh(self):
        subs = set()
        try:
            r = self.get(f'https://crt.sh/?q=%.{self.target}&output=json',
                         headers={'Accept': 'application/json'})
            if r and r.status_code == 200:
                entries = r.json()
                for entry in entries:
                    names = entry.get('name_value', '').split('\n')
                    for name in names:
                        name = name.strip().lstrip('*.')
                        if name.endswith(self.target) and name != self.target:
                            subs.add(name.lower())
        except Exception as e:
            self.log(f"crt.sh error: {e}", 'warning')
        return subs

    def _load_wordlist(self):
        if self.cfg.wordlist:
            try:
                with open(self.cfg.wordlist) as f:
                    return [line.strip() for line in f if line.strip()]
            except Exception as e:
                self.log(f"Wordlist load error: {e}", 'warning')
        return DEFAULT_WORDLIST

    def _brute_force(self, words):
        found = set()
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3

        def check(word):
            fqdn = f"{word}.{self.target}"
            try:
                resolver.resolve(fqdn, 'A')
                return fqdn
            except Exception:
                try:
                    resolver.resolve(fqdn, 'AAAA')
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
        try:
            cmd = ['subfinder', '-d', self.target, '-silent', '-o', '/tmp/sf_out.txt']
            if self.cfg.aggressive:
                cmd.extend(['-all'])
            subprocess.run(cmd, timeout=120, capture_output=True)
            with open('/tmp/sf_out.txt') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        subs.add(line)
        except Exception as e:
            self.log(f"subfinder error: {e}", 'debug')
        return subs

    def _amass(self):
        subs = set()
        try:
            cmd = ['amass', 'enum', '-passive', '-d', self.target, '-o', '/tmp/amass_out.txt']
            if self.cfg.aggressive:
                cmd = ['amass', 'enum', '-active', '-d', self.target, '-o', '/tmp/amass_out.txt']
            subprocess.run(cmd, timeout=300, capture_output=True)
            with open('/tmp/amass_out.txt') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        subs.add(line)
        except Exception as e:
            self.log(f"amass error: {e}", 'debug')
        return subs

    def _resolve_all(self, subs):
        resolved = {}
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3

        def resolve_one(sub):
            try:
                ans = resolver.resolve(sub, 'A')
                return sub, [str(r) for r in ans]
            except Exception:
                return sub, None

        with ThreadPoolExecutor(max_workers=self.cfg.threads) as ex:
            for sub, ips in ex.map(resolve_one, subs):
                if ips:
                    resolved[sub] = ips

        return resolved

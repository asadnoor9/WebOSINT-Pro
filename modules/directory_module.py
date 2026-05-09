"""
WebOSINT Pro - Directory & Endpoint Discovery Module
Common paths, API endpoints, hidden files (.env, .git, backups)
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from core.base_module import BaseModule


COMMON_PATHS = [
    # Admin panels
    '/admin', '/admin/', '/administrator', '/wp-admin', '/wp-login.php',
    '/phpmyadmin', '/pma', '/cpanel', '/webadmin', '/manager',
    '/admin/login', '/admin/index', '/backend', '/console',
    # Config / sensitive files
    '/.env', '/.env.local', '/.env.production', '/.env.backup',
    '/.git', '/.git/HEAD', '/.git/config', '/.gitignore',
    '/.svn', '/.svn/entries', '/.DS_Store', '/Thumbs.db',
    '/config.php', '/configuration.php', '/config.yml', '/config.yaml',
    '/settings.py', '/settings.php', '/database.yml', '/secrets.yml',
    '/wp-config.php', '/wp-config.php.bak', '/wp-config.php~',
    # Backups
    '/backup', '/backup.zip', '/backup.tar.gz', '/backup.sql',
    '/db.sql', '/dump.sql', '/database.sql', '/data.sql',
    '/site.tar.gz', '/website.zip', '/www.zip', '/html.tar.gz',
    # API
    '/api', '/api/v1', '/api/v2', '/api/v3', '/graphql',
    '/swagger', '/swagger.json', '/swagger.yaml',
    '/api-docs', '/openapi.json', '/openapi.yaml',
    '/rest', '/rest/v1', '/api/swagger',
    # Info disclosure
    '/info.php', '/phpinfo.php', '/test.php', '/info',
    '/server-info', '/server-status', '/nginx_status', '/status',
    '/health', '/health/', '/healthz', '/ping', '/version',
    '/debug', '/debug/', '/trace', '/actuator', '/actuator/env',
    '/actuator/health', '/actuator/info', '/actuator/mappings',
    '/__debug__/', '/django-admin/',
    # Logs
    '/logs', '/log', '/error.log', '/access.log', '/debug.log',
    '/application.log', '/server.log', '/error_log',
    # CMS
    '/robots.txt', '/sitemap.xml', '/crossdomain.xml', '/clientaccesspolicy.xml',
    '/feed', '/feed.xml', '/rss', '/atom.xml',
    # Cloud
    '/.well-known/security.txt', '/.well-known/acme-challenge/',
    '/s3', '/storage', '/uploads', '/upload', '/files', '/media',
    # Docs
    '/readme', '/readme.txt', '/readme.md', '/README', '/CHANGELOG',
    '/INSTALL', '/LICENSE', '/composer.json', '/package.json',
    '/requirements.txt', '/Gemfile', '/Pipfile',
]

INTERESTING_EXTENSIONS = ['.bak', '.old', '.backup', '.tmp', '.swp', '.~']


class Module(BaseModule):
    NAME = 'dirs'
    DESCRIPTION = 'Directory & endpoint discovery, hidden files, sensitive paths'

    def run(self):
        results = {
            'found': [],
            'sensitive': [],
            'api_endpoints': [],
            'backup_files': [],
        }

        base_url = f"https://{self.target}"

        # Load wordlist
        paths = list(COMMON_PATHS)
        if self.cfg.dir_wordlist:
            try:
                with open(self.cfg.dir_wordlist) as f:
                    extra = [line.strip() for line in f if line.strip() and line.startswith('/')]
                paths.extend(extra)
                self.log(f"Loaded {len(extra)} paths from wordlist")
            except Exception as e:
                self.log(f"Wordlist error: {e}", 'warning')

        # Scan
        found = self._scan_paths(base_url, paths)
        results['found'] = found
        results['found_count'] = len(found)

        # Categorize
        for item in found:
            path = item['path']
            if any(s in path for s in ['.env', '.git', 'config', 'backup', '.sql',
                                        'admin', 'phpinfo', 'actuator', 'debug', 'secret']):
                results['sensitive'].append(item)
            if any(p in path for p in ['/api', '/graphql', '/swagger', '/openapi', '/rest']):
                results['api_endpoints'].append(item)
            if any(ext in path for ext in INTERESTING_EXTENSIONS + ['.sql', '.tar', '.zip']):
                results['backup_files'].append(item)

        if results['sensitive']:
            results['_risk_sensitive_paths'] = 'critical' if any(
                '.env' in i['path'] or '.git' in i['path'] for i in results['sensitive']
            ) else 'high'

        if results['backup_files']:
            results['_risk_backup_files'] = 'high'

        return results

    def _scan_paths(self, base_url, paths):
        found = []

        def check(path):
            url = f"{base_url}{path}"
            try:
                r = self.session.get(
                    url, timeout=self.timeout, allow_redirects=False,
                    verify=False,
                    headers={'User-Agent': self.cfg.user_agent}
                )
                if r.status_code in (200, 201, 204, 301, 302, 307, 401, 403):
                    return {
                        'path': path,
                        'url': url,
                        'status': r.status_code,
                        'size': len(r.content),
                        'content_type': r.headers.get('content-type', ''),
                    }
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=self.cfg.threads) as ex:
            futures = {ex.submit(check, p): p for p in paths}
            for f in as_completed(futures):
                result = f.result()
                if result:
                    found.append(result)

        return sorted(found, key=lambda x: x['path'])

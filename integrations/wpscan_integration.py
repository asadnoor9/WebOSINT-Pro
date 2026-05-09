"""
WebOSINT Pro - WPScan Integration
WordPress vulnerability scanner.
"""

import subprocess
import shutil
import json


class WPScanIntegration:
    def __init__(self, config, logger):
        self.cfg = config
        self.logger = logger

    def is_wordpress(self, target):
        """Quick check if target is WordPress."""
        import requests
        try:
            r = requests.get(f"https://{target}/wp-login.php", timeout=10, verify=False)
            if r and ('wordpress' in r.text.lower() or 'wp-login' in r.text.lower()):
                return True
            r2 = requests.get(f"https://{target}/wp-includes/js/wp-emoji.js", timeout=5, verify=False)
            if r2 and r2.status_code == 200:
                return True
        except Exception:
            pass
        return False

    def run(self):
        if not shutil.which('wpscan'):
            return {'error': 'wpscan not installed', 'install': 'gem install wpscan'}

        if not self.is_wordpress(self.cfg.target):
            return {'skip': 'Target does not appear to be WordPress'}

        results = {}
        out_file = '/tmp/wpscan_out.json'

        cmd = [
            'wpscan',
            '--url', f"https://{self.cfg.target}",
            '--format', 'json',
            '--output', out_file,
            '--no-banner',
        ]

        if self.cfg.aggressive:
            cmd.extend(['--enumerate', 'p,t,u', '--plugins-detection', 'aggressive'])
        else:
            cmd.extend(['--enumerate', 'p,t', '--plugins-detection', 'passive'])

        self.logger.info(f"[wpscan] Scanning WordPress target")

        try:
            subprocess.run(cmd, timeout=180, capture_output=True)
            with open(out_file) as f:
                data = json.load(f)

            results['version'] = data.get('version', {})
            results['interesting_findings'] = data.get('interesting_findings', [])
            results['plugins'] = list(data.get('plugins', {}).keys())
            results['themes'] = list(data.get('main_theme', {}).get('name', ''))
            results['users'] = data.get('users', {})
            results['vulnerabilities'] = []

            # Extract plugin vulns
            for plugin, info in data.get('plugins', {}).items():
                for vuln in info.get('vulnerabilities', []):
                    results['vulnerabilities'].append({
                        'plugin': plugin,
                        'title': vuln.get('title', ''),
                        'cvss': vuln.get('cvss', {}).get('score'),
                        'cve': vuln.get('references', {}).get('cve', []),
                        'fixed_in': vuln.get('fixed_in', ''),
                    })

        except FileNotFoundError:
            results['note'] = 'wpscan output not found'
        except subprocess.TimeoutExpired:
            results['error'] = 'wpscan timed out'
        except Exception as e:
            results['error'] = str(e)

        return results

"""
WebOSINT Pro - CVE & CWE Mapping Module
Map detected services to known CVEs via NVD API, tag with CWE
"""

import json
from core.base_module import BaseModule


CWE_MAPPINGS = {
    'exposed_admin': 'CWE-284 Improper Access Control',
    'no_https': 'CWE-311 Missing Encryption of Sensitive Data',
    'no_hsts': 'CWE-319 Cleartext Transmission of Sensitive Information',
    'weak_tls': 'CWE-326 Inadequate Encryption Strength',
    'no_csp': 'CWE-79 Cross-site Scripting',
    'no_xframe': 'CWE-1021 Improper Restriction of Rendered UI Layers',
    'clickjacking': 'CWE-1021 Improper Restriction of Rendered UI Layers',
    'exposed_secrets': 'CWE-312 Cleartext Storage of Sensitive Information',
    'no_spf': 'CWE-290 Authentication Bypass by Spoofing',
    'no_dmarc': 'CWE-290 Authentication Bypass by Spoofing',
    'zone_transfer': 'CWE-200 Exposure of Sensitive Information',
    'open_redirect': 'CWE-601 URL Redirection to Untrusted Site',
    'exposed_db': 'CWE-306 Missing Authentication for Critical Function',
    'directory_listing': 'CWE-548 Exposure of Information Through Directory Listing',
    'backup_files': 'CWE-530 Exposure of Backup File to Unauthorized Control Sphere',
    'self_signed_cert': 'CWE-295 Improper Certificate Validation',
    'cookie_no_secure': 'CWE-614 Sensitive Cookie in HTTPS Without Secure Attribute',
    'cookie_no_httponly': 'CWE-1004 Sensitive Cookie Without HttpOnly Flag',
    'graphql_introspection': 'CWE-200 Exposure of Sensitive Information',
    'jwt_none_alg': 'CWE-347 Improper Verification of Cryptographic Signature',
    'api_docs_exposed': 'CWE-200 Exposure of Sensitive Information',
    'dangerousmethods': 'CWE-650 Trusting HTTP Permission Methods on the Server Side',
}

# Service → known CVE queries
SERVICE_CVE_MAP = {
    'Apache': 'apache httpd',
    'Nginx': 'nginx',
    'IIS': 'microsoft iis',
    'OpenSSH': 'openssh',
    'MySQL': 'mysql',
    'PostgreSQL': 'postgresql',
    'MongoDB': 'mongodb',
    'Redis': 'redis',
    'Elasticsearch': 'elasticsearch',
    'WordPress': 'wordpress',
    'Joomla': 'joomla',
    'Drupal': 'drupal',
    'Tomcat': 'apache tomcat',
    'Jenkins': 'jenkins',
}


class Module(BaseModule):
    NAME = 'cve'
    DESCRIPTION = 'CVE/CWE mapping via NVD API + finding correlation'

    NVD_API = 'https://services.nvd.nist.gov/rest/json/cves/2.0'

    def run(self):
        results = {
            'cwe_findings': [],
            'cve_lookups': {},
            'recommendations': [],
        }

        # CWE correlation from scan context
        # We infer from findings passed via config context or stored results
        # This module reads from the controller's accumulated findings
        cwe_tags = self._infer_cwes()
        results['cwe_findings'] = cwe_tags

        # CVE lookup for detected services
        services = self._get_detected_services()
        for service in services[:5]:  # rate limit
            cves = self._lookup_cves(service)
            if cves:
                results['cve_lookups'][service] = cves

        # Build recommendations
        results['recommendations'] = self._build_recommendations(cwe_tags)

        if any(c.get('severity') == 'CRITICAL' for c in cwe_tags):
            results['_risk_critical_cwe'] = 'critical'

        return results

    def _infer_cwes(self):
        """Statically map common web recon findings to CWEs."""
        findings = []

        # We check common indicators - in production these come from other modules
        base = f"https://{self.target}"
        try:
            r = self.get(base, verify=False)
            if r:
                headers = {k.lower(): v for k, v in r.headers.items()}

                if 'strict-transport-security' not in headers:
                    findings.append({
                        'finding': 'Missing HSTS header',
                        'cwe': CWE_MAPPINGS['no_hsts'],
                        'severity': 'MEDIUM',
                        'recommendation': 'Add Strict-Transport-Security header',
                    })

                if 'content-security-policy' not in headers:
                    findings.append({
                        'finding': 'Missing Content-Security-Policy',
                        'cwe': CWE_MAPPINGS['no_csp'],
                        'severity': 'MEDIUM',
                        'recommendation': 'Implement Content-Security-Policy header',
                    })

                if 'x-frame-options' not in headers:
                    findings.append({
                        'finding': 'Missing X-Frame-Options (Clickjacking)',
                        'cwe': CWE_MAPPINGS['no_xframe'],
                        'severity': 'MEDIUM',
                        'recommendation': 'Add X-Frame-Options: DENY or SAMEORIGIN',
                    })

                if 'x-content-type-options' not in headers:
                    findings.append({
                        'finding': 'Missing X-Content-Type-Options',
                        'cwe': 'CWE-16 Configuration',
                        'severity': 'LOW',
                        'recommendation': 'Add X-Content-Type-Options: nosniff',
                    })

                # Information disclosure
                server = headers.get('server', '')
                if server:
                    findings.append({
                        'finding': f'Server version disclosure: {server}',
                        'cwe': 'CWE-200 Exposure of Sensitive Information',
                        'severity': 'LOW',
                        'recommendation': 'Remove or genericize Server header',
                    })

        except Exception as e:
            self.log(f"CWE inference error: {e}", 'debug')

        return findings

    def _get_detected_services(self):
        """Get list of services to CVE-check. In production, reads from scan results."""
        services = []
        # Basic HTTP probe to detect server
        try:
            r = self.get(f"https://{self.target}", verify=False)
            if r:
                server = r.headers.get('server', '')
                for svc, query in SERVICE_CVE_MAP.items():
                    if svc.lower() in server.lower():
                        services.append(query)
        except Exception:
            pass
        return services

    def _lookup_cves(self, keyword):
        """Query NVD API for recent CVEs related to a service."""
        try:
            params = {
                'keywordSearch': keyword,
                'resultsPerPage': 5,
                'startIndex': 0,
            }
            headers = {}
            if self.cfg.nvd_key:
                headers['apiKey'] = self.cfg.nvd_key

            r = self.session.get(
                self.NVD_API, params=params, headers=headers,
                timeout=15
            )
            if r and r.status_code == 200:
                data = r.json()
                cves = []
                for vuln in data.get('vulnerabilities', []):
                    cve = vuln.get('cve', {})
                    cve_id = cve.get('id', '')
                    desc = cve.get('descriptions', [{}])[0].get('value', '')[:200]
                    metrics = cve.get('metrics', {})

                    score = None
                    severity = 'UNKNOWN'
                    for metric_key in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                        metric = metrics.get(metric_key, [{}])
                        if metric:
                            score = metric[0].get('cvssData', {}).get('baseScore')
                            severity = metric[0].get('cvssData', {}).get('baseSeverity', 'UNKNOWN')
                            break

                    cves.append({
                        'id': cve_id,
                        'description': desc,
                        'score': score,
                        'severity': severity,
                        'published': cve.get('published', ''),
                    })
                return cves
        except Exception as e:
            self.log(f"NVD API error for '{keyword}': {e}", 'debug')
        return []

    def _build_recommendations(self, findings):
        recs = []
        for f in findings:
            recs.append({
                'priority': f.get('severity', 'LOW'),
                'issue': f.get('finding'),
                'fix': f.get('recommendation'),
                'reference': f.get('cwe'),
            })
        # Sort by priority
        priority_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        recs.sort(key=lambda x: priority_order.get(x['priority'], 5))
        return recs

"""
WebOSINT Pro - SIEM Detection Module
Exposed dashboards: Kibana, Splunk, Grafana, Graylog, ELK
"""

from core.base_module import BaseModule


SIEM_TARGETS = [
    {'name': 'Kibana', 'ports': [5601], 'paths': ['/', '/app/kibana', '/app/home'],
     'signatures': ['kibana', 'elastic', 'Discover', 'dashboards']},
    {'name': 'Grafana', 'ports': [3000], 'paths': ['/', '/login'],
     'signatures': ['grafana', 'Grafana', 'grafana-app']},
    {'name': 'Splunk', 'ports': [8000, 8089], 'paths': ['/', '/en-US/account/login'],
     'signatures': ['splunk', 'Splunk', 'splunkd']},
    {'name': 'Graylog', 'ports': [9000], 'paths': ['/', '/api'],
     'signatures': ['graylog', 'Graylog']},
    {'name': 'Elasticsearch', 'ports': [9200], 'paths': ['/', '/_cluster/health', '/_cat/indices'],
     'signatures': ['elasticsearch', 'cluster_name', 'tagline']},
    {'name': 'Prometheus', 'ports': [9090], 'paths': ['/', '/graph', '/metrics'],
     'signatures': ['prometheus', 'Prometheus', 'tsdb']},
    {'name': 'Jaeger', 'ports': [16686], 'paths': ['/'],
     'signatures': ['jaeger', 'Jaeger UI']},
    {'name': 'Zipkin', 'ports': [9411], 'paths': ['/'],
     'signatures': ['zipkin', 'Zipkin']},
    {'name': 'Chronograf', 'ports': [8888], 'paths': ['/'],
     'signatures': ['chronograf', 'Chronograf']},
]


class Module(BaseModule):
    NAME = 'siem'
    DESCRIPTION = 'SIEM/logging dashboard detection: Kibana, Splunk, Grafana'

    def run(self):
        results = {'detected': [], 'checks': []}

        for tool in SIEM_TARGETS:
            for port in tool['ports']:
                for scheme in ['http', 'https']:
                    for path in tool['paths']:
                        url = f"{scheme}://{self.target}:{port}{path}"
                        try:
                            r = self.session.get(url, timeout=5, verify=False,
                                                  allow_redirects=True)
                            if r and r.status_code in (200, 302, 401, 403):
                                body_lower = r.text.lower()
                                for sig in tool['signatures']:
                                    if sig.lower() in body_lower:
                                        entry = {
                                            'name': tool['name'],
                                            'url': url,
                                            'port': port,
                                            'status': r.status_code,
                                            'accessible': r.status_code == 200,
                                            'auth_required': r.status_code in (401, 403),
                                        }
                                        if entry not in results['detected']:
                                            results['detected'].append(entry)
                                        break
                        except Exception:
                            pass

        if results['detected']:
            any_open = any(d['accessible'] for d in results['detected'])
            results['_risk_siem_exposed'] = 'critical' if any_open else 'high'

        return results

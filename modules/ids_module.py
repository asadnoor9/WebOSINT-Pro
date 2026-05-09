"""
WebOSINT Pro - IDS/IPS Detection Module
Passive inference via response behavior patterns
"""

import time
import random
import statistics
from core.base_module import BaseModule


class Module(BaseModule):
    NAME = 'ids'
    DESCRIPTION = 'IDS/IPS passive inference from response behavior'

    IDS_INDICATORS = {
        'Connection reset on scan patterns': False,
        'Unusual RST packets': False,
        'Rate-based blocking detected': False,
        'Consistent 403 on probes': False,
        'Response time anomalies': False,
    }

    def run(self):
        results = {
            'ids_likely': False,
            'indicators': [],
            'latency_analysis': {},
            'behavioral_notes': [],
        }

        base_url = f"https://{self.target}"

        # Measure baseline latency
        baseline = self._measure_latency(base_url, 3)
        results['latency_analysis']['baseline_ms'] = baseline

        # Send slightly suspicious requests and measure response
        if not self.cfg.passive_only:
            suspicious_latency = self._measure_suspicious_latency(base_url)
            results['latency_analysis']['suspicious_ms'] = suspicious_latency

            if baseline and suspicious_latency:
                ratio = suspicious_latency / baseline if baseline > 0 else 1
                results['latency_analysis']['ratio'] = round(ratio, 2)
                if ratio > 3.0:
                    results['indicators'].append('Response time significantly higher for suspicious requests (possible IDS throttling)')
                    results['ids_likely'] = True

        # Check for consistent blocking patterns
        block_count = self._probe_for_blocks(base_url)
        if block_count >= 2:
            results['indicators'].append(f'Consistent blocking on {block_count} probe types (IDS/IPS signature matching)')
            results['ids_likely'] = True

        results['confidence'] = 'low'
        if len(results['indicators']) >= 2:
            results['confidence'] = 'medium'

        return results

    def _measure_latency(self, url, samples=3):
        times = []
        for _ in range(samples):
            start = time.time()
            try:
                self.session.get(url, timeout=self.timeout, verify=False)
                times.append((time.time() - start) * 1000)
            except Exception:
                pass
            time.sleep(0.2)
        return round(statistics.mean(times), 2) if times else None

    def _measure_suspicious_latency(self, base_url):
        probes = [
            f"{base_url}/../../../etc/passwd",
            f"{base_url}/?id=1 UNION SELECT 1,2,3--",
        ]
        times = []
        for url in probes:
            start = time.time()
            try:
                self.session.get(url, timeout=self.timeout, verify=False)
                times.append((time.time() - start) * 1000)
            except Exception:
                pass
        return round(statistics.mean(times), 2) if times else None

    def _probe_for_blocks(self, base_url):
        blocked = 0
        probes = [
            f"{base_url}/?file=../etc/passwd",
            f"{base_url}/admin/.htaccess",
        ]
        for url in probes:
            try:
                r = self.session.get(url, timeout=self.timeout, verify=False)
                if r and r.status_code in (403, 406, 429):
                    blocked += 1
            except Exception:
                pass
        return blocked

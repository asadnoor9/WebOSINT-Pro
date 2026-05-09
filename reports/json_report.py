"""
WebOSINT Pro - JSON Report Generator
"""

import json
from datetime import datetime


class JSONReport:
    def __init__(self, results: dict):
        self.results = results

    def save(self, path: str):
        report = {
            'tool': 'WebOSINT Pro',
            'version': '1.0.0',
            'generated': datetime.now().isoformat(),
            'meta': self.results.get('meta', {}),
            'summary': self.results.get('summary', {}),
            'findings': self.results.get('findings', {}),
            'errors': self.results.get('errors', {}),
        }

        with open(path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, default=str, ensure_ascii=False)

        return path

"""
WebOSINT Pro - WHOIS Module
"""

import whois
from datetime import datetime
from core.base_module import BaseModule


class Module(BaseModule):
    NAME = 'whois'
    DESCRIPTION = 'WHOIS lookup: registrar, owner, dates'

    def run(self):
        results = {}
        try:
            w = whois.whois(self.target)
            if not w:
                return {'error': 'No WHOIS data returned'}

            results['domain'] = str(w.domain_name or self.target)
            results['registrar'] = str(w.registrar or 'Unknown')
            results['registrant'] = str(w.org or w.registrant or 'Redacted')
            results['registrant_email'] = str(w.emails[0] if isinstance(w.emails, list) else w.emails or 'N/A')
            results['name_servers'] = [str(ns) for ns in (w.name_servers or [])]
            results['status'] = w.status if isinstance(w.status, list) else [str(w.status)]

            # Dates
            created = w.creation_date
            expires = w.expiration_date
            updated = w.updated_date

            def normalize_date(d):
                if isinstance(d, list):
                    d = d[0]
                if isinstance(d, datetime):
                    return d.isoformat()
                return str(d) if d else None

            results['created'] = normalize_date(created)
            results['expires'] = normalize_date(expires)
            results['updated'] = normalize_date(updated)

            # Expiry warning
            if expires:
                exp = expires[0] if isinstance(expires, list) else expires
                if isinstance(exp, datetime):
                    days_left = (exp - datetime.now()).days
                    results['days_until_expiry'] = days_left
                    if days_left < 30:
                        results['_expiry_warning'] = f"Expires in {days_left} days!"
                        results['_risk'] = 'medium'

            # DNSSEC in WHOIS
            results['dnssec'] = str(w.dnssec or 'unsigned')

        except Exception as e:
            self.log(f"WHOIS error: {e}", 'warning')
            results['error'] = str(e)

        return results

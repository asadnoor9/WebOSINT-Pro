"""
WebOSINT Pro - Mail Security Module
MX, SPF, DKIM, DMARC validation
"""

import dns.resolver
from core.base_module import BaseModule


DKIM_SELECTORS = [
    'default', 'google', 'mail', 'k1', 'k2', 'selector1', 'selector2',
    'dkim', 'smtp', 'email', 's1', 's2', 'mxvault', 'mandrill',
    'sendgrid', 'mailjet', 'amazonses', 'pm', 'mta',
]


class Module(BaseModule):
    NAME = 'mail'
    DESCRIPTION = 'Mail security: MX, SPF, DKIM, DMARC validation'

    def run(self):
        results = {}
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout

        # MX records
        mx = self._get_mx(resolver)
        results['mx_records'] = mx

        # SPF
        spf = self._get_spf(resolver)
        results['spf'] = spf
        if not spf.get('found'):
            results['_risk_no_spf'] = 'high'
        elif spf.get('all_mechanism') == '+all':
            results['_risk_spf_permissive'] = 'critical'

        # DMARC
        dmarc = self._get_dmarc(resolver)
        results['dmarc'] = dmarc
        if not dmarc.get('found'):
            results['_risk_no_dmarc'] = 'high'
        elif dmarc.get('policy') == 'none':
            results['_risk_dmarc_policy_none'] = 'medium'

        # DKIM
        dkim = self._probe_dkim(resolver)
        results['dkim'] = dkim
        if not dkim.get('found'):
            results['_risk_no_dkim'] = 'medium'

        # MTA-STS
        mta_sts = self._check_mta_sts()
        results['mta_sts'] = mta_sts

        # BIMI
        bimi = self._check_bimi(resolver)
        results['bimi'] = bimi

        # Email spoofing risk assessment
        can_spoof = (not spf.get('found') or
                     spf.get('all_mechanism') in ['+all', '?all', '~all'] or
                     not dmarc.get('found') or
                     dmarc.get('policy') == 'none')
        results['email_spoofing_risk'] = 'HIGH' if can_spoof else 'LOW'
        if can_spoof:
            results['_risk_email_spoofing'] = 'high'

        return results

    def _get_mx(self, resolver):
        try:
            answers = resolver.resolve(self.target, 'MX')
            return sorted(
                [{'priority': r.preference, 'host': str(r.exchange)} for r in answers],
                key=lambda x: x['priority']
            )
        except Exception:
            return []

    def _get_spf(self, resolver):
        result = {'found': False, 'record': None, 'all_mechanism': None, 'issues': []}
        try:
            answers = resolver.resolve(self.target, 'TXT')
            for rdata in answers:
                txt = str(rdata).strip('"')
                if txt.startswith('v=spf1'):
                    result['found'] = True
                    result['record'] = txt

                    # Parse mechanisms
                    parts = txt.split()
                    mechanisms = []
                    for part in parts[1:]:
                        if part.startswith(('include:', 'ip4:', 'ip6:', 'a', 'mx', 'ptr')):
                            mechanisms.append(part)
                        elif part in ('+all', '-all', '~all', '?all', 'all'):
                            result['all_mechanism'] = part

                    result['mechanisms'] = mechanisms

                    if result['all_mechanism'] == '+all':
                        result['issues'].append('CRITICAL: +all allows anyone to send as your domain')
                    elif result['all_mechanism'] == '~all':
                        result['issues'].append('WARNING: ~all (softfail) - emails may not be rejected')
                    elif result['all_mechanism'] == '?all':
                        result['issues'].append('WARNING: ?all (neutral) - provides no protection')
                    elif result['all_mechanism'] == '-all':
                        result['issues'].append('OK: -all enforces SPF rejection')
                    break
        except Exception:
            pass
        return result

    def _get_dmarc(self, resolver):
        result = {'found': False, 'record': None, 'policy': None, 'issues': []}
        try:
            answers = resolver.resolve(f'_dmarc.{self.target}', 'TXT')
            for rdata in answers:
                txt = str(rdata).strip('"')
                if txt.startswith('v=DMARC1'):
                    result['found'] = True
                    result['record'] = txt

                    # Parse tags
                    tags = {}
                    for part in txt.split(';'):
                        part = part.strip()
                        if '=' in part:
                            k, v = part.split('=', 1)
                            tags[k.strip()] = v.strip()

                    result['policy'] = tags.get('p', 'none')
                    result['subdomain_policy'] = tags.get('sp', tags.get('p', 'none'))
                    result['pct'] = tags.get('pct', '100')
                    result['rua'] = tags.get('rua', '')
                    result['ruf'] = tags.get('ruf', '')
                    result['adkim'] = tags.get('adkim', 'r')
                    result['aspf'] = tags.get('aspf', 'r')

                    if result['policy'] == 'none':
                        result['issues'].append('Policy=none: monitoring only, emails not rejected')
                    if result['pct'] != '100':
                        result['issues'].append(f"pct={result['pct']}: DMARC only applied to {result['pct']}% of mail")
                    break
        except Exception:
            pass
        return result

    def _probe_dkim(self, resolver):
        result = {'found': False, 'selectors': []}
        for selector in DKIM_SELECTORS:
            query = f"{selector}._domainkey.{self.target}"
            try:
                answers = resolver.resolve(query, 'TXT')
                for rdata in answers:
                    txt = str(rdata).strip('"')
                    if 'v=DKIM1' in txt or 'p=' in txt:
                        result['found'] = True
                        result['selectors'].append({
                            'selector': selector,
                            'record': txt[:200],
                        })
                        break
            except Exception:
                pass
        return result

    def _check_mta_sts(self):
        result = {'found': False}
        try:
            r = self.get(f"https://mta-sts.{self.target}/.well-known/mta-sts.txt")
            if r and r.status_code == 200:
                result['found'] = True
                result['policy'] = r.text[:500]
        except Exception:
            pass
        return result

    def _check_bimi(self, resolver):
        result = {'found': False}
        try:
            answers = resolver.resolve(f'default._bimi.{self.target}', 'TXT')
            for rdata in answers:
                txt = str(rdata).strip('"')
                if 'v=BIMI1' in txt:
                    result['found'] = True
                    result['record'] = txt
        except Exception:
            pass
        return result

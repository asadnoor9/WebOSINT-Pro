"""
WebOSINT Pro - IP Intelligence Module
ASN, ISP, geo, reputation, blacklist checks
"""

import socket
import ipaddress
from core.base_module import BaseModule


BLACKLIST_APIS = [
    'https://api.abuseipdb.com/api/v2/check',
    'https://www.virustotal.com/vtapi/v2/ip-address/report',
]

DNSBL_ZONES = [
    'zen.spamhaus.org',
    'bl.spamcop.net',
    'dnsbl.sorbs.net',
    'combined.abuse.ch',
    'cbl.abuseat.org',
]


class Module(BaseModule):
    NAME = 'ip'
    DESCRIPTION = 'IP intelligence: ASN, ISP, geo, reputation, blacklists'

    def run(self):
        results = {}

        # Resolve target to IP
        ips = self._resolve_ips()
        if not ips:
            self.log("Could not resolve IPs")
            return {'error': 'Could not resolve target IPs'}

        results['resolved_ips'] = ips
        self.log(f"Resolved IPs: {ips}")

        for ip in ips[:4]:
            ip_data = self._analyze_ip(ip)
            results[ip] = ip_data

        return results

    def _resolve_ips(self):
        ips = []
        # IPv4
        try:
            for info in socket.getaddrinfo(self.target, None, socket.AF_INET):
                ip = info[4][0]
                if ip not in ips:
                    ips.append(ip)
        except Exception:
            pass
        # IPv6
        try:
            for info in socket.getaddrinfo(self.target, None, socket.AF_INET6):
                ip = info[4][0]
                if ip not in ips:
                    ips.append(ip)
        except Exception:
            pass
        return ips

    def _analyze_ip(self, ip):
        data = {'ip': ip}

        # IP type checks
        try:
            addr = ipaddress.ip_address(ip)
            data['version'] = f'IPv{addr.version}'
            data['is_private'] = addr.is_private
            data['is_loopback'] = addr.is_loopback
            data['is_multicast'] = addr.is_multicast
        except ValueError:
            pass

        # GeoIP via ip-api.com (free, no key)
        geo = self._geoip(ip)
        if geo:
            data['geo'] = geo

        # ASN via bgpview
        asn = self._get_asn(ip)
        if asn:
            data['asn'] = asn

        # DNSBL check
        bl_hits = self._dnsbl_check(ip)
        data['blacklisted'] = len(bl_hits) > 0
        if bl_hits:
            data['blacklist_hits'] = bl_hits
            data['_risk'] = 'high'

        return data

    def _geoip(self, ip):
        try:
            r = self.get(f'http://ip-api.com/json/{ip}?fields=country,regionName,city,isp,org,as,timezone,mobile,proxy,hosting')
            if r and r.status_code == 200:
                return r.json()
        except Exception as e:
            self.log(f"GeoIP failed for {ip}: {e}", 'debug')
        return None

    def _get_asn(self, ip):
        try:
            r = self.get(f'https://api.bgpview.io/ip/{ip}')
            if r and r.status_code == 200:
                data = r.json()
                prefixes = data.get('data', {}).get('prefixes', [])
                if prefixes:
                    p = prefixes[0]
                    return {
                        'asn': p.get('asn', {}).get('asn'),
                        'name': p.get('asn', {}).get('name'),
                        'description': p.get('asn', {}).get('description'),
                        'prefix': p.get('prefix'),
                    }
        except Exception as e:
            self.log(f"ASN lookup failed for {ip}: {e}", 'debug')
        return None

    def _dnsbl_check(self, ip):
        hits = []
        try:
            # Reverse IP for DNSBL
            parts = ip.split('.')
            if len(parts) == 4:
                rev = '.'.join(reversed(parts))
                import dns.resolver
                for zone in DNSBL_ZONES:
                    try:
                        query = f"{rev}.{zone}"
                        dns.resolver.resolve(query, 'A')
                        hits.append(zone)
                    except Exception:
                        pass
        except Exception as e:
            self.log(f"DNSBL check error: {e}", 'debug')
        return hits

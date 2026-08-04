"""
WebOSINT Pro - DNS Module
A, AAAA, MX, NS, TXT, SOA, CNAME, SRV, DNSSEC, zone transfer, PTR
"""

import socket

import dns.dnssec
import dns.name
import dns.query
import dns.rdatatype
import dns.resolver
import dns.zone

from core.base_module import BaseModule


class Module(BaseModule):
    NAME = "dns"
    DESCRIPTION = "DNS records enumeration + DNSSEC + zone transfer"

    RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV", "CAA"]

    def run(self):
        results = {}
        self.log(f"Starting DNS enumeration for {self.target}")

        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout

        # Enumerate record types
        for rtype in self.RECORD_TYPES:
            records = self._query(resolver, self.target, rtype)
            if records:
                results[rtype] = records
                self.log(f"{rtype}: {records}", "debug")

        # PTR reverse lookup
        a_records = results.get("A", [])
        if a_records:
            ptr_results = {}
            for ip in a_records[:5]:
                ptr = self._reverse_dns(ip)
                if ptr:
                    ptr_results[ip] = ptr
            if ptr_results:
                results["PTR"] = ptr_results

        # Zone transfer attempt
        ns_records = results.get("NS", [])
        if ns_records and not self.cfg.passive_only:
            zt = self._zone_transfer(ns_records)
            if zt:
                results["ZONE_TRANSFER"] = zt
                results["_vuln_zone_transfer"] = True
                self.log("ZONE TRANSFER SUCCESSFUL - misconfiguration!", "warning")

        # DNSSEC validation
        dnssec = self._check_dnssec(resolver)
        results["DNSSEC"] = dnssec

        return results

    def _query(self, resolver, domain, rtype):
        try:
            answers = resolver.resolve(domain, rtype)
            records = []
            for rdata in answers:
                if rtype == "MX":
                    records.append(f"{rdata.preference} {rdata.exchange}")
                elif rtype == "SOA":
                    records.append(
                        {
                            "mname": str(rdata.mname),
                            "rname": str(rdata.rname),
                            "serial": rdata.serial,
                            "refresh": rdata.refresh,
                            "retry": rdata.retry,
                            "expire": rdata.expire,
                            "minimum": rdata.minimum,
                        }
                    )
                elif rtype == "SRV":
                    records.append(f"{rdata.priority} {rdata.weight} {rdata.port} {rdata.target}")
                elif rtype in ("TXT", "CAA"):
                    records.append(str(rdata))
                else:
                    records.append(str(rdata))
            return records
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
        ):
            return []
        except Exception as e:
            self.log(f"Query {rtype} error: {e}", "debug")
            return []

    def _reverse_dns(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return None

    def _zone_transfer(self, ns_records):
        results = []
        for ns in ns_records[:3]:
            ns_clean = ns.rstrip(".")
            try:
                z = dns.zone.from_xfr(dns.query.xfr(ns_clean, self.target, timeout=5))
                for name, _node in z.nodes.items():
                    results.append(str(name))
                if results:
                    return results
            except Exception:
                pass
        return []

    def _check_dnssec(self, resolver):
        try:
            request = dns.message.make_query(self.target, dns.rdatatype.DNSKEY, want_dnssec=True)
            response = dns.query.udp(request, "8.8.8.8", timeout=5)
            if response.answer:
                return {"enabled": True, "status": "DNSKEY present"}
            return {"enabled": False, "status": "No DNSKEY record"}
        except Exception as e:
            return {"enabled": False, "status": f"Check failed: {e}"}

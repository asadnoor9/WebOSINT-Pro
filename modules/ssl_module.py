"""
WebOSINT Pro - SSL/TLS Module
Certificate parsing, expiry, weak protocols, cipher suites
"""

import datetime
import socket
import ssl

from core.base_module import BaseModule

WEAK_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]
WEAK_CIPHERS = [
    "RC4",
    "DES",
    "3DES",
    "MD5",
    "NULL",
    "EXPORT",
    "anon",
    "ADH",
    "AECDH",
    "RC2",
    "IDEA",
]


class Module(BaseModule):
    NAME = "ssl"
    DESCRIPTION = "SSL/TLS: cert parsing, expiry, weak protocols, ciphers"

    def run(self):
        results = {}
        host = self.target
        port = 443

        # Get certificate
        cert_info = self._get_cert(host, port)
        if cert_info:
            results["certificate"] = cert_info

        # Expiry check
        if cert_info and "not_after" in cert_info:
            expiry = self._check_expiry(cert_info["not_after"])
            results["expiry"] = expiry
            if expiry.get("days_left", 999) < 30:
                results["_risk_cert_expiry"] = "high"
            elif expiry.get("days_left", 999) < 90:
                results["_risk_cert_expiry"] = "medium"

        # Protocol support
        results["protocols"] = self._check_protocols(host, port)

        # Weak protocol detection
        weak_protos = [
            p for p, supported in results["protocols"].items() if supported and p in WEAK_PROTOCOLS
        ]
        if weak_protos:
            results["weak_protocols"] = weak_protos
            results["_risk_weak_protocols"] = "high"

        # Cipher info from default connection
        cipher_info = self._get_cipher_info(host, port)
        results["cipher_info"] = cipher_info

        # Self-signed check
        if cert_info:
            results["self_signed"] = cert_info.get("issuer") == cert_info.get("subject")
            if results["self_signed"]:
                results["_risk_self_signed"] = "high"

        # SAN check
        if cert_info:
            sans = cert_info.get("san", [])
            results["subject_alt_names"] = sans
            # Wildcard certs
            wildcards = [s for s in sans if s.startswith("*")]
            results["wildcard_certs"] = wildcards

        return results

    def _get_cert(self, host, port):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()

            if not cert:
                return None

            # Parse subject
            subject = {}
            for field in cert.get("subject", []):
                for k, v in field:
                    subject[k] = v

            issuer = {}
            for field in cert.get("issuer", []):
                for k, v in field:
                    issuer[k] = v

            # SANs
            sans = []
            for _typ, val in cert.get("subjectAltName", []):
                sans.append(val)

            return {
                "subject": subject,
                "issuer": issuer,
                "version": cert.get("version"),
                "serial_number": cert.get("serialNumber"),
                "not_before": cert.get("notBefore"),
                "not_after": cert.get("notAfter"),
                "san": sans,
                "signature_algorithm": cert.get("signatureAlgorithm", "Unknown"),
            }
        except Exception as e:
            self.log(f"Cert fetch error: {e}", "debug")
            return None

    def _check_expiry(self, not_after_str):
        try:
            expiry_date = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry_date - datetime.datetime.utcnow()).days
            return {
                "expiry_date": expiry_date.isoformat(),
                "days_left": days_left,
                "expired": days_left < 0,
            }
        except Exception as e:
            return {"error": str(e)}

    def _check_protocols(self, host, port):
        protocols = {}
        proto_map = {
            "TLSv1": ssl.PROTOCOL_TLSv1 if hasattr(ssl, "PROTOCOL_TLSv1") else None,
            "TLSv1.1": ssl.PROTOCOL_TLSv1_1 if hasattr(ssl, "PROTOCOL_TLSv1_1") else None,
            "TLSv1.2": ssl.PROTOCOL_TLSv1_2 if hasattr(ssl, "PROTOCOL_TLSv1_2") else None,
        }

        for proto_name, proto_const in proto_map.items():
            if proto_const is None:
                protocols[proto_name] = "unavailable"
                continue
            try:
                ctx = ssl.SSLContext(proto_const)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((host, port), timeout=3) as s:
                    with ctx.wrap_socket(s, server_hostname=host):
                        protocols[proto_name] = True
            except ssl.SSLError:
                protocols[proto_name] = False
            except Exception:
                protocols[proto_name] = False

        # TLS 1.3
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            if hasattr(ssl, "TLSVersion"):
                ctx.minimum_version = ssl.TLSVersion.TLSv1_3
                ctx.maximum_version = ssl.TLSVersion.TLSv1_3
            with socket.create_connection((host, port), timeout=3) as s:
                with ctx.wrap_socket(s, server_hostname=host):
                    protocols["TLSv1.3"] = True
        except Exception:
            protocols["TLSv1.3"] = False

        return protocols

    def _get_cipher_info(self, host, port):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=self.timeout) as s:
                with ctx.wrap_socket(s, server_hostname=host) as ss:
                    cipher = ss.cipher()
                    return {
                        "name": cipher[0],
                        "protocol": cipher[1],
                        "bits": cipher[2],
                        "weak": any(w in cipher[0].upper() for w in WEAK_CIPHERS),
                    }
        except Exception:
            return {}

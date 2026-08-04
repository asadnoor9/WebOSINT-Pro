"""
WebOSINT Pro - Honeypot & Decoy Detection Module
Tarpits, fake services, abnormal latency, inconsistent banners
"""

import socket
import statistics
import time

from core.base_module import BaseModule


class Module(BaseModule):
    NAME = "honeypot"
    DESCRIPTION = "Honeypot/decoy detection: latency, banners, behavior analysis"

    def run(self):
        results = {
            "honeypot_likely": False,
            "confidence": "low",
            "indicators": [],
            "latency": {},
            "banner_analysis": {},
        }

        # Tarpit detection: abnormally slow responses
        latency_indicator = self._check_tarpit()
        results["latency"] = latency_indicator
        if latency_indicator.get("tarpit_likely"):
            results["indicators"].append(
                "Possible tarpit: extremely high response latency detected"
            )
            results["honeypot_likely"] = True

        # Banner inconsistency
        banner_issues = self._check_banner_consistency()
        results["banner_analysis"] = banner_issues
        if banner_issues.get("inconsistent"):
            results["indicators"].append("Inconsistent server banners across ports/requests")
            results["honeypot_likely"] = True

        # Check for honeypot-specific patterns
        patterns = self._check_honeypot_patterns()
        if patterns:
            results["indicators"].extend(patterns)
            results["honeypot_likely"] = True

        # Too-perfect open ports
        perfect_ports = self._check_all_ports_open()
        if perfect_ports:
            results["indicators"].append(
                "Suspicious: too many ports responding (possible honeypot)"
            )
            results["honeypot_likely"] = True

        if len(results["indicators"]) >= 2:
            results["confidence"] = "medium"
        if len(results["indicators"]) >= 3:
            results["confidence"] = "high"

        return results

    def _check_tarpit(self):
        result = {"tarpit_likely": False, "avg_ms": None}
        samples = []
        for _ in range(3):
            start = time.time()
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(10)
                s.connect((self.target, 80))
                s.send(b"GET / HTTP/1.0\r\n\r\n")
                s.recv(64)
                s.close()
                elapsed = (time.time() - start) * 1000
                samples.append(elapsed)
            except Exception:
                pass

        if samples:
            avg = statistics.mean(samples)
            result["avg_ms"] = round(avg, 2)
            result["samples"] = samples
            if avg > 5000:  # > 5 seconds average is suspicious
                result["tarpit_likely"] = True
                result["note"] = f"Average response: {avg:.0f}ms (normal is <1000ms)"

        return result

    def _check_banner_consistency(self):
        banners = {}
        result = {"inconsistent": False, "banners": {}}

        ports_to_check = [80, 443, 22, 21]
        for port in ports_to_check:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                s.connect((self.target, port))
                banner = s.recv(256).decode("utf-8", errors="replace").strip()
                s.close()
                if banner:
                    banners[port] = banner
            except Exception:
                pass

        result["banners"] = banners

        # Check HTTP server header consistency
        server_headers = []
        for scheme in ["http", "https"]:
            try:
                r = self.session.get(f"{scheme}://{self.target}", timeout=5)
                if r:
                    sv = r.headers.get("server", "").lower()
                    if sv:
                        server_headers.append(sv)
            except Exception:
                pass

        if len(set(server_headers)) > 1:
            result["inconsistent"] = True
            result["note"] = f"Different server headers: {set(server_headers)}"

        return result

    def _check_honeypot_patterns(self):
        indicators = []
        # Known honeypot strings
        honeypot_sigs = [
            "kippo",
            "cowrie",
            "dionaea",
            "honeyd",
            "glastopf",
            "opencanary",
            "canarytokens",
            "thinkst",
        ]
        try:
            r = self.session.get(f"https://{self.target}", timeout=5)
            if r:
                body_lower = r.text.lower()
                for sig in honeypot_sigs:
                    if sig in body_lower:
                        indicators.append(f"Honeypot signature detected: '{sig}'")
        except Exception:
            pass
        return indicators

    def _check_all_ports_open(self):
        # If >20 of 25 sampled ports respond, likely honeypot
        test_ports = [
            1,
            7,
            9,
            13,
            17,
            19,
            23,
            25,
            37,
            42,
            43,
            53,
            70,
            79,
            107,
            109,
            110,
            111,
            113,
            115,
            117,
            119,
            135,
            139,
            143,
        ]
        open_count = 0
        for port in test_ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                if s.connect_ex((self.target, port)) == 0:
                    open_count += 1
                s.close()
            except Exception:
                pass

        return open_count > 18

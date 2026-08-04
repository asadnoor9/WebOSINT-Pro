"""
WebOSINT Pro - Port Scanning Module
nmap integration with service/version detection
"""

import shutil
import socket
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from core.base_module import BaseModule

TOP_PORTS = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    111,
    135,
    139,
    143,
    443,
    445,
    993,
    995,
    1723,
    3306,
    3389,
    5432,
    5900,
    6379,
    8080,
    8443,
    8888,
    9000,
    9200,
    9300,
    27017,
    27018,
    6443,
    2379,
    2380,
    5044,
    514,
    1514,
    1515,
    5601,
    8200,
    9090,
    16686,
    9411,
]


class Module(BaseModule):
    NAME = "ports"
    DESCRIPTION = "Port scanning via nmap + fallback socket scanner"

    # Hard ceiling for a single nmap invocation, in seconds.
    NMAP_TIMEOUT_SECONDS = 300

    def run(self):
        results = {}

        if not self.cfg.passive_only and shutil.which("nmap"):
            nmap_results = self._nmap_scan()
            results.update(nmap_results)
        else:
            self.log("nmap not found or passive mode - using socket scanner")
            open_ports = self._socket_scan()
            results["open_ports"] = open_ports
            results["scanner"] = "socket"

        # Flag dangerous ports
        dangerous = self._flag_dangerous(results.get("open_ports", results.get("ports", {})))
        if dangerous:
            results["dangerous_ports"] = dangerous
            results["_risk_open_ports"] = "high"

        return results

    def _nmap_scan(self):
        target = self.target
        results = {"scanner": "nmap"}
        out_file = self.cfg.get_temp_file(".nmap.xml")

        # Build nmap command based on profile
        if self.cfg.aggressive:
            cmd = [
                "nmap",
                "-sV",
                "-sC",
                "-O",
                "--script=banner",
                "--traceroute",
                "-p",
                "1-10000",
                "-T4",
                "-oX",
                out_file,
                target,
            ]
        elif self.cfg.stealth:
            cmd = [
                "nmap",
                "-sS",
                "-sV",
                "-O",
                "--traceroute",
                "-T2",
                "-p",
                ",".join(map(str, TOP_PORTS)),
                "-oX",
                out_file,
                target,
            ]
        else:
            cmd = [
                "nmap",
                "-sV",
                "-O",
                "--traceroute",
                "-T3",
                "--top-ports",
                "1000",
                "-oX",
                out_file,
                target,
            ]

        try:
            nmap_timeout = int(getattr(self.cfg, "nmap_timeout", 0) or self.NMAP_TIMEOUT_SECONDS)
            proc = self.runner.run(cmd, timeout=nmap_timeout)
            results["nmap_stdout"] = proc.stdout[-2000:] if proc.stdout else ""

            # Parse XML output
            parsed = self._parse_nmap_xml(out_file)
            results.update(parsed)
            results["open_ports"] = list(parsed.get("ports", {}).keys())
            results["open_count"] = len(results["open_ports"])

        except OSError:
            results["error"] = "nmap timed out"
        except Exception as e:
            results["error"] = str(e)
            self.log(f"nmap error: {e}", "warning")
        finally:
            Path(out_file).unlink(missing_ok=True)

        return results

    def _parse_nmap_xml(self, xml_path):
        parsed = {
            "ports": {},
            "state_breakdown": {"open": 0, "closed": 0, "filtered": 0},
            "os_guess": [],
            "traceroute": [],
            "host_discovery": {},
            "latency": "",
        }
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()

            for host in root.findall("host"):
                status = host.find("status")
                if status is not None:
                    parsed["host_discovery"] = {
                        "state": status.get("state", ""),
                        "reason": status.get("reason", ""),
                    }
                times = host.find("times")
                if times is not None:
                    parsed["latency"] = times.get("srtt", "")
                for extraports in host.findall(".//extraports"):
                    state = extraports.get("state", "")
                    count = int(extraports.get("count", "0") or 0)
                    if state:
                        parsed["state_breakdown"][state] = (
                            parsed["state_breakdown"].get(state, 0) + count
                        )
                for port_elem in host.findall(".//port"):
                    port_id = port_elem.get("portid")
                    protocol = port_elem.get("protocol", "tcp")

                    state_elem = port_elem.find("state")
                    state = state_elem.get("state") if state_elem is not None else "unknown"
                    parsed["state_breakdown"][state] = parsed["state_breakdown"].get(state, 0) + 1
                    if state != "open":
                        continue

                    service_elem = port_elem.find("service")
                    service_info = {"state": state, "confidence": "medium"}
                    if service_elem is not None:
                        service_info = {
                            **service_info,
                            "name": service_elem.get("name", "unknown"),
                            "product": service_elem.get("product", ""),
                            "version": service_elem.get("version", ""),
                            "extrainfo": service_elem.get("extrainfo", ""),
                            "ostype": service_elem.get("ostype", ""),
                            "tunnel": service_elem.get("tunnel", ""),
                            "banner": " ".join(
                                value
                                for value in [
                                    service_elem.get("product", ""),
                                    service_elem.get("version", ""),
                                    service_elem.get("extrainfo", ""),
                                ]
                                if value
                            ),
                            "confidence": service_elem.get("conf", "medium"),
                        }

                    # Scripts
                    scripts = {}
                    for script in port_elem.findall("script"):
                        scripts[script.get("id")] = script.get("output", "")

                    key = f"{port_id}/{protocol}"
                    parsed["ports"][key] = {**service_info, "scripts": scripts}

                for osmatch in host.findall(".//osmatch"):
                    parsed["os_guess"].append(
                        {
                            "name": osmatch.get("name", ""),
                            "accuracy": osmatch.get("accuracy", ""),
                        }
                    )

                for hop in host.findall(".//trace/hop"):
                    parsed["traceroute"].append(
                        {
                            "ttl": hop.get("ttl", ""),
                            "ipaddr": hop.get("ipaddr", ""),
                            "rtt": hop.get("rtt", ""),
                            "host": hop.get("host", ""),
                        }
                    )

        except Exception as e:
            self.log(f"nmap XML parse error: {e}", "debug")
        return parsed

    def _socket_scan(self):
        open_ports = []

        def check_port(port):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                result = s.connect_ex((self.target, port))
                s.close()
                if result == 0:
                    return port
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=min(50, self.cfg.threads * 2)) as ex:
            for result in ex.map(check_port, TOP_PORTS):
                if result:
                    open_ports.append(result)

        return sorted(open_ports)

    def _flag_dangerous(self, ports_data):
        dangerous_services = {
            21: "FTP",
            23: "Telnet",
            1723: "PPTP VPN",
            135: "RPC",
            139: "NetBIOS",
            445: "SMB",
            3389: "RDP",
            5900: "VNC",
            3306: "MySQL",
            5432: "PostgreSQL",
            6379: "Redis",
            27017: "MongoDB",
            9200: "Elasticsearch",
        }
        found = []
        if isinstance(ports_data, list):
            for port in ports_data:
                if port in dangerous_services:
                    found.append(f"{port} ({dangerous_services[port]})")
        elif isinstance(ports_data, dict):
            for key in ports_data:
                try:
                    port = int(key.split("/")[0])
                    if port in dangerous_services:
                        found.append(f"{port} ({dangerous_services[port]})")
                except Exception:
                    pass
        return found

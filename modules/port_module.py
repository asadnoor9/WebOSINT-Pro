"""
WebOSINT Pro - Port Scanning Module
nmap integration with service/version detection
"""

import subprocess
import shutil
import socket
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from core.base_module import BaseModule


TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
             993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443,
             8888, 9200, 9300, 27017, 27018, 6443, 2379, 2380]


class Module(BaseModule):
    NAME = 'ports'
    DESCRIPTION = 'Port scanning via nmap + fallback socket scanner'

    def run(self):
        results = {}

        if not self.cfg.passive_only and shutil.which('nmap'):
            nmap_results = self._nmap_scan()
            results.update(nmap_results)
        else:
            self.log("nmap not found or passive mode - using socket scanner")
            open_ports = self._socket_scan()
            results['open_ports'] = open_ports
            results['scanner'] = 'socket'

        # Flag dangerous ports
        dangerous = self._flag_dangerous(results.get('open_ports', results.get('ports', {})))
        if dangerous:
            results['dangerous_ports'] = dangerous
            results['_risk_open_ports'] = 'high'

        return results

    def _nmap_scan(self):
        target = self.target
        results = {'scanner': 'nmap'}

        # Build nmap command based on profile
        if self.cfg.aggressive:
            cmd = ['nmap', '-sV', '-sC', '-O', '--script=banner',
                   '-p', '1-10000', '-T4', '--open',
                   '-oX', '/tmp/nmap_out.xml', target]
        elif self.cfg.stealth:
            cmd = ['nmap', '-sS', '-sV', '-T2', '--open',
                   '-p', ','.join(map(str, TOP_PORTS)),
                   '-oX', '/tmp/nmap_out.xml', target]
        else:
            cmd = ['nmap', '-sV', '-T3', '--open',
                   '--top-ports', '1000',
                   '-oX', '/tmp/nmap_out.xml', target]

        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=300
            )
            results['nmap_stdout'] = proc.stdout[-2000:] if proc.stdout else ''

            # Parse XML output
            ports = self._parse_nmap_xml('/tmp/nmap_out.xml')
            results['ports'] = ports
            results['open_ports'] = list(ports.keys())
            results['open_count'] = len(ports)

        except subprocess.TimeoutExpired:
            results['error'] = 'nmap timed out'
        except Exception as e:
            results['error'] = str(e)
            self.log(f"nmap error: {e}", 'warning')

        return results

    def _parse_nmap_xml(self, xml_path):
        ports = {}
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()

            for host in root.findall('host'):
                for port_elem in host.findall('.//port'):
                    port_id = port_elem.get('portid')
                    protocol = port_elem.get('protocol', 'tcp')

                    state_elem = port_elem.find('state')
                    if state_elem is None or state_elem.get('state') != 'open':
                        continue

                    service_elem = port_elem.find('service')
                    service_info = {}
                    if service_elem is not None:
                        service_info = {
                            'name': service_elem.get('name', 'unknown'),
                            'product': service_elem.get('product', ''),
                            'version': service_elem.get('version', ''),
                            'extrainfo': service_elem.get('extrainfo', ''),
                            'ostype': service_elem.get('ostype', ''),
                            'tunnel': service_elem.get('tunnel', ''),
                        }

                    # Scripts
                    scripts = {}
                    for script in port_elem.findall('script'):
                        scripts[script.get('id')] = script.get('output', '')

                    key = f"{port_id}/{protocol}"
                    ports[key] = {**service_info, 'scripts': scripts}

        except Exception as e:
            self.log(f"nmap XML parse error: {e}", 'debug')
        return ports

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
            21: 'FTP', 23: 'Telnet', 1723: 'PPTP VPN',
            135: 'RPC', 139: 'NetBIOS', 445: 'SMB',
            3389: 'RDP', 5900: 'VNC',
            3306: 'MySQL', 5432: 'PostgreSQL',
            6379: 'Redis', 27017: 'MongoDB',
            9200: 'Elasticsearch',
        }
        found = []
        if isinstance(ports_data, list):
            for port in ports_data:
                if port in dangerous_services:
                    found.append(f"{port} ({dangerous_services[port]})")
        elif isinstance(ports_data, dict):
            for key in ports_data:
                try:
                    port = int(key.split('/')[0])
                    if port in dangerous_services:
                        found.append(f"{port} ({dangerous_services[port]})")
                except Exception:
                    pass
        return found

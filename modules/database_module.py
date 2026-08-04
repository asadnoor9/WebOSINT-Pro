"""
WebOSINT Pro - Database Detection Module
MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch, exposed services
"""

import socket
from concurrent.futures import ThreadPoolExecutor

from core.base_module import BaseModule

DB_PORTS = {
    3306: {"name": "MySQL", "banner_check": b"mysql"},
    5432: {"name": "PostgreSQL", "banner_check": b"PostgreSQL"},
    6379: {"name": "Redis", "probe": b"PING\r\n", "response": b"+PONG"},
    27017: {"name": "MongoDB", "banner_check": b"mongo"},
    27018: {"name": "MongoDB (secondary)", "banner_check": b"mongo"},
    9200: {"name": "Elasticsearch", "http": True, "path": "/"},
    9300: {"name": "Elasticsearch Transport", "banner_check": b"elastic"},
    5984: {"name": "CouchDB", "http": True, "path": "/"},
    6432: {"name": "PgBouncer", "banner_check": b"pgbouncer"},
    11211: {"name": "Memcached", "probe": b"stats\r\n", "response": b"STAT"},
    2181: {"name": "Zookeeper", "probe": b"mntr", "response": b"zk_"},
    5601: {"name": "Kibana", "http": True, "path": "/"},
    8086: {"name": "InfluxDB", "http": True, "path": "/ping"},
    5000: {"name": "Flask/API (common)", "http": True, "path": "/"},
    8000: {"name": "Django/API (common)", "http": True, "path": "/"},
}


class Module(BaseModule):
    NAME = "database"
    DESCRIPTION = "Database detection: MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch"

    def run(self):
        results = {"exposed_databases": [], "checks": {}}

        def check_db(port, info):
            result = {"port": port, "service": info["name"], "exposed": False}
            target_ip = self.target

            # HTTP-based check
            if info.get("http"):
                path = info.get("path", "/")
                try:
                    r = self.session.get(f"http://{target_ip}:{port}{path}", timeout=5)
                    if r and r.status_code in (200, 401, 403):
                        result["exposed"] = True
                        result["status_code"] = r.status_code
                        result["banner"] = r.text[:200]
                        return result
                except Exception:
                    pass
                return result

            # TCP banner grab
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                s.connect((target_ip, port))

                probe = info.get("probe", b"")
                if probe:
                    s.send(probe)

                banner = s.recv(1024)
                s.close()

                if banner:
                    result["exposed"] = True
                    result["banner"] = banner[:200].decode("utf-8", errors="replace")

                    # Check expected response
                    expected = info.get("response", b"")
                    if expected and expected in banner:
                        result["confirmed"] = True
                    elif info.get("banner_check") and info["banner_check"] in banner.lower():
                        result["confirmed"] = True

            except (TimeoutError, ConnectionRefusedError):
                pass
            except Exception as e:
                self.log(f"DB check {port} error: {e}", "debug")

            return result

        with ThreadPoolExecutor(max_workers=self.cfg.threads) as ex:
            futures = {ex.submit(check_db, port, info): port for port, info in DB_PORTS.items()}
            for f in futures:
                res = f.result()
                results["checks"][res["port"]] = res
                if res.get("exposed"):
                    results["exposed_databases"].append(
                        {
                            "port": res["port"],
                            "service": res["service"],
                            "confirmed": res.get("confirmed", False),
                            "banner": res.get("banner", ""),
                        }
                    )

        if results["exposed_databases"]:
            results["_risk_exposed_db"] = "critical"

        return results

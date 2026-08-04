"""
WebOSINT Pro - WebSocket Detection Module
"""

import re

from core.base_module import BaseModule


class Module(BaseModule):
    NAME = "websocket"
    DESCRIPTION = "WebSocket detection (ws:// and wss://)"

    WS_PATHS = [
        "/ws",
        "/websocket",
        "/socket",
        "/socket.io",
        "/ws/v1",
        "/live",
        "/stream",
        "/events",
        "/push",
        "/notify",
    ]

    def run(self):
        results = {"detected": False, "endpoints": [], "libraries": []}
        base = f"https://{self.target}"

        r = self.get(base)
        if r:
            body = r.text
            # Find WebSocket URLs in source
            ws_pattern = re.compile(r'wss?://[^\s"\'<>]+', re.I)
            for match in ws_pattern.finditer(body):
                url = match.group()
                if url not in results["endpoints"]:
                    results["endpoints"].append(url)
                    results["detected"] = True

            # Library signatures
            if "socket.io" in body.lower():
                results["libraries"].append("Socket.IO")
            if "sockjs" in body.lower():
                results["libraries"].append("SockJS")
            if "stomp" in body.lower():
                results["libraries"].append("STOMP")
            if "websocket" in body.lower():
                results["detected"] = True

        # Probe common WS upgrade paths
        for path in self.WS_PATHS:
            url = f"https://{self.target}{path}"
            try:
                r = self.session.get(
                    url,
                    timeout=self.timeout,
                    headers={
                        "Upgrade": "websocket",
                        "Connection": "Upgrade",
                        "Sec-WebSocket-Version": "13",
                        "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                    },
                )
                if r and r.status_code in (101, 200, 400, 426):
                    results["detected"] = True
                    if url not in results["endpoints"]:
                        results["endpoints"].append(url)
            except Exception:
                pass

        return results

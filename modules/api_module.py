"""
WebOSINT Pro - API Security Module
JWT detection/decoding, API endpoint mapping, GraphQL detection
"""

import base64
import json
import re

from core.base_module import BaseModule


class Module(BaseModule):
    NAME = "api"
    DESCRIPTION = "API security: JWT decode, GraphQL, endpoint mapping"

    GRAPHQL_PATHS = [
        "/graphql",
        "/graphiql",
        "/api/graphql",
        "/v1/graphql",
        "/query",
        "/gql",
        "/graph",
    ]
    API_DOC_PATHS = [
        "/swagger.json",
        "/swagger.yaml",
        "/openapi.json",
        "/openapi.yaml",
        "/api-docs",
        "/api/swagger",
        "/v1/api-docs",
        "/v2/api-docs",
        "/v3/api-docs",
    ]

    def run(self):
        results = {}
        base = f"https://{self.target}"

        # GraphQL detection
        gql = self._detect_graphql(base)
        results["graphql"] = gql
        if gql.get("detected"):
            results["_risk_graphql"] = "medium"

        # API docs
        api_docs = self._find_api_docs(base)
        results["api_docs"] = api_docs
        if api_docs:
            results["_risk_api_docs_exposed"] = "medium"

        # JWT in cookies/headers
        jwts = self._find_jwts(base)
        results["jwts"] = jwts
        if jwts:
            results["_risk_jwt"] = "info"

        # REST endpoint probing
        endpoints = self._probe_rest_endpoints(base)
        results["rest_endpoints"] = endpoints

        return results

    def _detect_graphql(self, base):
        result = {"detected": False, "endpoints": [], "introspection": False}

        for path in self.GRAPHQL_PATHS:
            url = f"{base}{path}"
            # POST introspection query
            try:
                r = self.session.post(
                    url, json={"query": "{__schema{queryType{name}}}"}, timeout=self.timeout
                )
                if r and r.status_code in (200, 400):
                    body = r.text
                    if "data" in body or "__schema" in body or "errors" in body:
                        result["detected"] = True
                        result["endpoints"].append(url)
                        if "__schema" in body:
                            result["introspection"] = True
                            result["_introspection_enabled"] = True

                # Also GET check
                rg = self.get(url)
                if rg and rg.status_code in (200, 400, 405):
                    if "graphql" in rg.text.lower() or "graphiql" in rg.text.lower():
                        result["detected"] = True
                        if url not in result["endpoints"]:
                            result["endpoints"].append(url)
            except Exception:
                pass

        return result

    def _find_api_docs(self, base):
        found = []
        for path in self.API_DOC_PATHS:
            url = f"{base}{path}"
            r = self.get(url)
            if r and r.status_code == 200 and len(r.content) > 100:
                ct = r.headers.get("content-type", "")
                if any(t in ct for t in ["json", "yaml", "html", "text"]):
                    # Try to extract endpoint count
                    endpoints = []
                    try:
                        data = r.json()
                        paths = data.get("paths", {})
                        endpoints = list(paths.keys())[:30]
                    except Exception:
                        pass
                    found.append(
                        {
                            "url": url,
                            "size": len(r.content),
                            "content_type": ct,
                            "endpoints_found": len(endpoints),
                            "sample_endpoints": endpoints[:10],
                        }
                    )
        return found

    def _find_jwts(self, base):
        jwts = []
        r = self.get(base)
        if not r:
            return jwts

        # Check cookies
        for cookie in r.cookies:
            val = cookie.value
            if self._is_jwt(val):
                decoded = self._decode_jwt(val)
                jwts.append(
                    {
                        "location": f"cookie:{cookie.name}",
                        "header": decoded.get("header"),
                        "payload": decoded.get("payload"),
                        "algorithm": decoded.get("header", {}).get("alg"),
                        "issues": self._check_jwt_issues(decoded),
                    }
                )

        # Check response headers for Authorization
        for header in ["authorization", "x-auth-token", "x-access-token"]:
            val = r.headers.get(header, "")
            if val.lower().startswith("bearer "):
                token = val[7:]
                if self._is_jwt(token):
                    decoded = self._decode_jwt(token)
                    jwts.append(
                        {
                            "location": f"header:{header}",
                            "header": decoded.get("header"),
                            "payload": decoded.get("payload"),
                            "algorithm": decoded.get("header", {}).get("alg"),
                            "issues": self._check_jwt_issues(decoded),
                        }
                    )

        # Scan body for JWT patterns
        body = r.text
        jwt_pattern = re.compile(r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]+")
        for match in jwt_pattern.finditer(body):
            token = match.group()
            decoded = self._decode_jwt(token)
            jwts.append(
                {
                    "location": "response_body",
                    "token_preview": token[:40] + "...",
                    "header": decoded.get("header"),
                    "payload": decoded.get("payload"),
                    "algorithm": decoded.get("header", {}).get("alg"),
                    "issues": self._check_jwt_issues(decoded),
                }
            )

        return jwts

    def _is_jwt(self, value):
        parts = value.split(".")
        return len(parts) == 3 and parts[0].startswith("eyJ")

    def _decode_jwt(self, token):
        result = {}
        try:
            parts = token.split(".")

            # Add padding
            def b64pad(s):
                return s + "=" * (-len(s) % 4)

            header = json.loads(base64.urlsafe_b64decode(b64pad(parts[0])))
            payload = json.loads(base64.urlsafe_b64decode(b64pad(parts[1])))
            result["header"] = header
            result["payload"] = payload
        except Exception as e:
            result["error"] = str(e)
        return result

    def _check_jwt_issues(self, decoded):
        issues = []
        header = decoded.get("header", {})
        payload = decoded.get("payload", {})

        alg = header.get("alg", "").upper()
        if alg == "NONE":
            issues.append("CRITICAL: alg=none - signature bypass possible")
        elif alg in ("HS256", "HS384", "HS512"):
            issues.append(f"Symmetric algorithm {alg} - secret could be brute-forced")
        elif alg.startswith("RS") or alg.startswith("ES"):
            pass  # Asymmetric, generally fine

        import time

        exp = payload.get("exp")
        if exp and exp < time.time():
            issues.append("Token is expired but may still be accepted")

        return issues

    def _probe_rest_endpoints(self, base):
        common = [
            "/api/users",
            "/api/user",
            "/api/me",
            "/api/profile",
            "/api/accounts",
            "/api/admin",
            "/api/config",
            "/api/settings",
            "/api/v1/users",
            "/api/v2/users",
            "/v1/users",
            "/v2/users",
        ]
        found = []
        for path in common:
            url = f"{base}{path}"
            r = self.get(url)
            if r and r.status_code != 404:
                found.append({"path": path, "status": r.status_code, "size": len(r.content)})
        return found

"""
WebOSINT Pro - Engagement scope.

A ``Scope`` describes what a user is authorized to test: a set of in-scope
domains (with subdomain matching) and/or CIDR networks. It is consumed by the
safety gate to refuse anything outside the declared engagement, which is the
normal way to feed a bug-bounty program's scope into the tool.

Scope files (``--scope-file``) may be:
  * YAML (if PyYAML is installed): ``{domains: [...], networks: [...]}``
  * JSON: ``{"domains": [...], "networks": [...]}``
  * Plain text: one domain or CIDR per line, ``#`` comments allowed.
"""

from __future__ import annotations

import ipaddress
import json
import os
from collections.abc import Iterable

try:  # optional dependency
    import yaml  # type: ignore
except Exception:  # pragma: no cover - optional
    yaml = None


class ScopeError(ValueError):
    """Raised when a scope file cannot be parsed or is empty."""


def _norm_domain(domain: str) -> str:
    domain = domain.strip().lower()
    for prefix in ("http://", "https://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix) :]
    domain = domain.split("/", 1)[0]
    domain = domain.lstrip("*.")
    return domain.rstrip(".")


class Scope:
    def __init__(
        self,
        domains: Iterable[str] | None = None,
        networks: Iterable[ipaddress._BaseNetwork] | None = None,
        source: str | None = None,
    ) -> None:
        self.domains = sorted({_norm_domain(d) for d in (domains or []) if d})
        self.networks = list(networks or [])
        self.source = source

    def __bool__(self) -> bool:
        return bool(self.domains or self.networks)

    def __len__(self) -> int:
        return len(self.domains) + len(self.networks)

    # ------------------------------------------------------------------
    def contains_domain(self, target: str) -> bool:
        t = _norm_domain(target)
        return any(t == d or t.endswith("." + d) for d in self.domains)

    def contains_ip(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self.networks)

    def contains(self, target: str, resolved_ips: Iterable[str] | None = None) -> bool:
        if self.contains_domain(target):
            return True
        if self.contains_ip(target):
            return True
        return any(self.contains_ip(ip) for ip in resolved_ips or [])

    # ------------------------------------------------------------------
    @classmethod
    def from_file(cls, path: str) -> Scope:
        if not path or not os.path.exists(path):
            raise ScopeError(f"Scope file not found: {path}")
        with open(path, encoding="utf-8") as fh:
            raw = fh.read()

        data: dict | None = None
        stripped = raw.strip()
        if stripped.startswith("{"):
            try:
                data = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ScopeError(f"Invalid JSON scope file: {exc}") from exc
        elif yaml is not None and (":" in stripped and not stripped.startswith("#")):
            try:
                loaded = yaml.safe_load(raw)
                if isinstance(loaded, dict):
                    data = loaded
            except Exception:
                data = None

        domains: list[str] = []
        networks: list[ipaddress._BaseNetwork] = []

        if isinstance(data, dict):
            domains = [str(d) for d in (data.get("domains") or [])]
            for n in data.get("networks") or []:
                networks.append(_parse_network(str(n)))
        else:
            for line in raw.splitlines():
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                if "/" in line and _looks_like_cidr(line):
                    networks.append(_parse_network(line))
                else:
                    domains.append(line)

        scope = cls(domains=domains, networks=networks, source=path)
        if not scope:
            raise ScopeError(f"Scope file declares no domains or networks: {path}")
        return scope


def _looks_like_cidr(value: str) -> bool:
    head = value.split("/", 1)[0]
    return (head.count(".") == 3) or (":" in head)


def _parse_network(value: str) -> ipaddress._BaseNetwork:
    try:
        return ipaddress.ip_network(value.strip(), strict=False)
    except ValueError as exc:
        raise ScopeError(f"Invalid network in scope file: {value!r} ({exc})") from exc

"""
WebOSINT Pro - Safety, Authorization & Target Validation Engine

This is the single gate that every network action must pass through.

Enforced policy:
  1. Explicit authorization (--authorized) plus a typed/interactive target
     confirmation is mandatory before any network action.
  2. Targets are validated and classified (domain / IP / localhost / private).
  3. Localhost, private, reserved, link-local, multicast and loopback ranges
     are blocked by default (opt in with --allow-private for lab use).
  4. Optional allowlist (configs/allowlist.json or --allowlist) restricts scans
     to explicitly approved scopes.
  5. Passive OSINT is the default. Active probing requires --active.
  6. TLS verification is on by default; --insecure-tls is an explicit opt-in
     and marks every result produced under it as untrusted.
  7. Redirect targets are re-validated to prevent SSRF-style pivots.
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import sys
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

# ── Blocked network ranges (RFC1918 + reserved/special use) ────────────────────
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),  # CGNAT
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),  # multicast
    ipaddress.ip_network("240.0.0.0/4"),  # reserved
    ipaddress.ip_network("255.255.255.255/32"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("fc00::/7"),  # unique local
    ipaddress.ip_network("fe80::/10"),  # link-local
    ipaddress.ip_network("ff00::/8"),  # multicast
]

# Cloud metadata endpoints are always blocked, even with --allow-private.
_METADATA_ADDRESSES = {
    "169.254.169.254",
    "fd00:ec2::254",
    "metadata.google.internal",
    "metadata.goog",
}

ALLOWED_URL_SCHEMES = ("http", "https")

ALLOWLIST_PATH = Path(__file__).resolve().parent.parent / "configs" / "allowlist.json"

_DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.IGNORECASE)


class AuthorizationError(Exception):
    """Raised when a network action is attempted without a passing safety gate."""


class TargetBlockedError(Exception):
    """Raised when a host or URL is outside the approved, safe scope."""


@dataclass(slots=True)
class SafetyPolicy:
    """Immutable-ish description of what this run is permitted to do."""

    authorized: bool = False
    confirmed: bool = False
    active: bool = False
    allow_private: bool = False
    insecure_tls: bool = False
    allow_redirects: bool = True
    max_redirects: int = 3
    allowlist: tuple[str, ...] = ()
    telemetry: bool = False

    @property
    def passive_only(self) -> bool:
        return not self.active

    @property
    def verify_tls(self) -> bool:
        return not self.insecure_tls

    @property
    def results_trusted(self) -> bool:
        return not self.insecure_tls

    def require_authorized(self) -> None:
        if not (self.authorized and self.confirmed):
            raise AuthorizationError(
                "Authorization gate not passed. Re-run with --authorized and confirm the target."
            )

    def require_active(self, what: str) -> None:
        """Guard an active/intrusive code path."""
        self.require_authorized()
        if not self.active:
            raise AuthorizationError(f"Active check '{what}' requires the --active flag.")


@dataclass
class SafetyResult:
    allowed: bool = False
    target: str = ""
    target_type: str = "unknown"  # ip | domain | localhost | private
    is_private: bool = False
    is_localhost: bool = False
    resolved_ips: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    allowlisted: bool = False
    policy: SafetyPolicy = field(default_factory=SafetyPolicy)


def is_blocked_ip(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True when the address is private, loopback, reserved or otherwise unsafe."""
    if str(addr) in _METADATA_ADDRESSES:
        return True
    if any(addr in net for net in _PRIVATE_NETWORKS):
        return True
    return bool(
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


def normalize_host(value: str) -> str:
    """Lower-case, strip scheme/port/path and trailing dots from a host string."""
    host = str(value or "").strip().lower()
    if "://" in host:
        host = urlsplit(host).hostname or ""
    host = host.split("/")[0].strip()
    if host.startswith("[") and "]" in host:  # IPv6 literal
        host = host[1 : host.index("]")]
    elif host.count(":") == 1:
        host = host.split(":")[0]
    return host.rstrip(".")


class SafetyController:
    """
    Central safety gate — must pass before any scan or request proceeds.

    Typical use::

        controller = SafetyController(policy)
        result = controller.validate(target)
        if not result.allowed:
            ...  # abort
        controller.check_url(url)  # before every request
    """

    def __init__(
        self,
        policy: SafetyPolicy | None = None,
        allowlist_path: Path | None = None,
    ) -> None:
        self.policy = policy or SafetyPolicy()
        self._allowlist_path = allowlist_path or ALLOWLIST_PATH
        loaded = list(self.policy.allowlist) or self._load_allowlist()
        self._allowlist: list[str] = [normalize_host(e) or str(e).lower() for e in loaded if e]
        self._approved_hosts: set[str] = set()

    # ── Public API ────────────────────────────────────────────────────────────

    @property
    def allowlist(self) -> list[str]:
        return list(self._allowlist)

    def validate(self, target: str, authorized: bool | None = None) -> SafetyResult:
        """Full pre-scan validation. ``allowed`` is True only if every check passes."""
        result = SafetyResult(target=normalize_host(target), policy=self.policy)

        is_authorized = self.policy.authorized if authorized is None else bool(authorized)
        if not is_authorized:
            result.errors.append(
                "Authorization not confirmed. Re-run with --authorized after confirming you "
                "have explicit written permission to test this target."
            )
            return result

        if not self.policy.confirmed and authorized is None:
            result.errors.append(
                "Target confirmation missing. Provide --confirm-target <target> matching -t."
            )
            return result

        self._classify_target(result.target, result)
        if result.errors:
            return result

        # Blocked ranges
        if (result.is_localhost or result.is_private) and not self.policy.allow_private:
            result.errors.append(
                "Target resolves to a localhost/private/reserved address and is blocked by "
                "default. Use --allow-private only for systems you own in a lab."
            )
            return result
        if result.target in _METADATA_ADDRESSES:
            result.errors.append("Cloud metadata endpoints are always blocked.")
            return result

        # Allowlist
        if self._allowlist:
            result.allowlisted = self._match_allowlist(result.target)
            if not result.allowlisted:
                result.errors.append(
                    f"Target '{result.target}' is not in the configured allowlist. Add it to "
                    "configs/allowlist.json or pass --allowlist."
                )
                return result
        else:
            result.warnings.append(
                "No allowlist configured — operating in open-target mode. "
                "Ensure written authorization covers this scope."
            )

        if self.policy.active:
            result.warnings.append(
                "ACTIVE mode enabled — intrusive probes will be sent to the target."
            )
        if self.policy.insecure_tls:
            result.warnings.append(
                "TLS verification disabled — all results from this run are marked UNTRUSTED."
            )

        self._approved_hosts.add(result.target)
        for ip in result.resolved_ips:
            self._approved_hosts.add(ip)
        result.allowed = True
        return result

    def check_host(self, host: str) -> str:
        """Validate a host before connecting. Raises TargetBlockedError when unsafe."""
        self.policy.require_authorized()
        name = normalize_host(host)
        if not name:
            raise TargetBlockedError("Empty host is not allowed.")
        if name in _METADATA_ADDRESSES:
            raise TargetBlockedError("Cloud metadata endpoint blocked.")

        try:
            addr = ipaddress.ip_address(name)
        except ValueError:
            addr = None

        if addr is not None and is_blocked_ip(addr) and not self.policy.allow_private:
            raise TargetBlockedError("Private, loopback or reserved address blocked.")

        if self._allowlist and not self._match_allowlist(name):
            raise TargetBlockedError(f"Host '{name}' is outside the configured allowlist.")

        if addr is None and not self.policy.allow_private:
            for ip in self._resolve(name):
                try:
                    if is_blocked_ip(ipaddress.ip_address(ip)):
                        raise TargetBlockedError(
                            "Host resolves to a private or reserved address (possible DNS rebind)."
                        )
                except ValueError:
                    continue
        return name

    def check_url(self, url: str) -> str:
        """Validate a full URL (scheme + host) before a request or redirect."""
        parts = urlsplit(str(url))
        if parts.scheme.lower() not in ALLOWED_URL_SCHEMES:
            raise TargetBlockedError(f"URL scheme '{parts.scheme}' is not allowed.")
        if not parts.hostname:
            raise TargetBlockedError("URL has no host component.")
        self.check_host(parts.hostname)
        return url

    def is_url_allowed(self, url: str) -> bool:
        try:
            self.check_url(url)
            return True
        except (TargetBlockedError, AuthorizationError):
            return False

    def require_active(self, what: str) -> None:
        self.policy.require_active(what)

    def confirm_interactive(self, target: str, active: bool = False) -> bool:
        """Interactive authorization prompt. Returns True only on an exact match."""
        from utils.output import ColorOutput as C

        banner = f"""
{C.YELLOW}+--------------------------------------------------------------+
|                    !  LEGAL WARNING  !                       |
+--------------------------------------------------------------+
|  This tool is for AUTHORIZED security testing ONLY.          |
|  Unauthorized scanning may violate:                          |
|   - Computer Fraud and Abuse Act (CFAA)                      |
|   - Computer Misuse Act (UK)                                 |
|   - EU Directive on Attacks Against Information Systems      |
|                                                              |
|  Only test systems you OWN or have EXPLICIT WRITTEN          |
|  permission to assess. Authors assume NO responsibility.     |
+--------------------------------------------------------------+{C.RESET}
"""
        print(banner)
        if active:
            print(
                f"  {C.RED}{C.BOLD}ACTIVE MODE:{C.RESET} intrusive probes (port scans, directory "
                f"brute force, payload probes) will be sent to the target."
            )
        print(f"  {C.BOLD}Target:{C.RESET} {C.CYAN}{target}{C.RESET}")
        print(
            "\n  Type the target exactly to confirm written authorization "
            "(or press Enter to abort): ",
            end="",
        )
        try:
            answer = input().strip().lower()
        except (KeyboardInterrupt, EOFError):
            answer = ""

        if answer != normalize_host(target):
            print(f"\n{C.RED}[!] Authorization not confirmed. Exiting.{C.RESET}\n")
            return False
        print()
        return True

    def emergency_stop(self) -> None:
        """Called on KeyboardInterrupt — flush and exit cleanly."""
        from utils.output import ColorOutput as C

        print(f"\n\n{C.YELLOW}[!] Emergency stop — cancelling in-flight work…{C.RESET}")
        sys.exit(130)

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _classify_target(self, target: str, result: SafetyResult) -> None:
        if not target:
            result.errors.append("No target provided.")
            return

        if target in ("localhost", "localhost.localdomain", "127.0.0.1", "::1"):
            result.target_type = "localhost"
            result.is_localhost = True
            result.is_private = True
            result.resolved_ips = [target]
            return

        try:
            addr = ipaddress.ip_address(target)
        except ValueError:
            addr = None

        if addr is not None:
            result.target_type = "ip"
            result.resolved_ips = [str(addr)]
            result.is_private = is_blocked_ip(addr)
            result.is_localhost = addr.is_loopback
            if result.is_private:
                result.target_type = "private"
            return

        if not _DOMAIN_RE.match(target):
            result.errors.append(
                f"Invalid target format: '{target}'. Provide a domain (example.com) or IP."
            )
            return

        result.target_type = "domain"
        resolved = self._resolve(target)
        if not resolved:
            result.warnings.append(
                f"Could not resolve '{target}' — continuing with an unresolved target."
            )
            return

        result.resolved_ips = resolved
        blocked = []
        for ip in resolved:
            try:
                blocked.append(is_blocked_ip(ipaddress.ip_address(ip)))
            except ValueError:
                blocked.append(False)
        result.is_private = any(blocked)
        result.is_localhost = any(
            ipaddress.ip_address(ip).is_loopback for ip in resolved if _safe_ip(ip) is not None
        )

    @staticmethod
    def _resolve(host: str) -> list[str]:
        try:
            infos = socket.getaddrinfo(host, None)
        except (socket.gaierror, UnicodeError, OSError):
            return []
        out: list[str] = []
        for info in infos:
            ip = str(info[4][0])
            if ip not in out:
                out.append(ip)
        return sorted(out)

    def _load_allowlist(self) -> list[str]:
        path = self._allowlist_path
        if not path or not Path(path).exists():
            return []
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return []
        targets = data.get("targets", []) if isinstance(data, dict) else data
        return [str(t).strip().lower() for t in targets or [] if str(t).strip()]

    def _match_allowlist(self, host: str) -> bool:
        target = normalize_host(host)
        for raw in self._allowlist:
            entry = str(raw).lstrip("*.").rstrip(".").lower()
            if not entry:
                continue
            if target == entry or target.endswith("." + entry):
                return True
            try:
                network = ipaddress.ip_network(entry, strict=False)
                if ipaddress.ip_address(target) in network:
                    return True
            except ValueError:
                continue
        return False


def _safe_ip(value: str):
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None

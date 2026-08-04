"""
WebOSINT Pro - Redaction & Data Minimization

Central place for scrubbing sensitive values before they reach the console,
log files, reports, or exception messages.

Redacted by default:
  * API keys / tokens / bearer credentials / passwords
  * Cookies, Set-Cookie and Authorization headers
  * Email addresses (unless the detail level explicitly keeps them)
  * Private / internal IP addresses
  * Local filesystem paths (only the file name is kept)
"""

from __future__ import annotations

import ipaddress
import os
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any

REDACTED = "[REDACTED]"


class DetailLevel(str, Enum):
    """Data minimization levels, lowest exposure first."""

    MINIMAL = "minimal"
    STANDARD = "standard"
    DETAILED = "detailed"

    @classmethod
    def parse(cls, value: str | None) -> DetailLevel:
        try:
            return cls(str(value).strip().lower())
        except ValueError:
            return cls.STANDARD


# ── Key names whose values are never printed or persisted ───────────────────────

SENSITIVE_KEY_PARTS: tuple[str, ...] = (
    "api_key",
    "apikey",
    "authorization",
    "auth_token",
    "access_token",
    "bearer",
    "cookie",
    "credential",
    "passwd",
    "password",
    "private_key",
    "proxy",
    "refresh_token",
    "secret",
    "session_key",
    "set-cookie",
    "shodan_key",
    "nvd_key",
    "token",
    "x-api-key",
)

# Keys that are personally identifying and only kept at "detailed" level.
PII_KEY_PARTS: tuple[str, ...] = (
    "email",
    "emails",
    "registrant",
    "owner",
    "admin_contact",
    "tech_contact",
    "phone",
    "address",
    "person",
    "contact",
)

# Raw payload keys that are only persisted when explicitly enabled.
RAW_KEY_PARTS: tuple[str, ...] = (
    "raw_body",
    "raw_response",
    "response_body",
    "request_headers",
    "resp_headers",
    "body_snippet",
    "query_string",
)


_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # Authorization: Bearer <token>
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 " + REDACTED),
    # key=value style secrets in URLs, CLI strings and log lines
    (
        re.compile(
            r"(?i)\b((?:[a-z0-9]+[_-])*"
            r"(?:api[_-]?key|apikey|token|secret|password|passwd|pwd|"
            r"access[_-]?token|auth|session|shodan[_-]?key|nvd[_-]?key)"
            r"\s*[:=]\s*)[\"']?[^\s\"'&,;]{4,}"
        ),
        r"\1" + REDACTED,
    ),
    # JWTs
    (
        re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"),
        REDACTED,
    ),
    # AWS access key IDs
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), REDACTED),
    # Generic long hex/base62 secrets (Shodan-style 32 char keys)
    (re.compile(r"\b[A-Za-z0-9]{32,64}\b(?=\s*(?:$|[\"',;)]))"), REDACTED),
)

_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_HOME_RE = re.compile(r"(?:[A-Za-z]:\\|/)(?:[\w.-]+[/\\]){2,}([\w.-]+)")


def _is_internal_ip(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return bool(
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


def mask_secret(value: str, keep: int = 2) -> str:
    """Mask a secret while keeping a short recognisable suffix."""
    text = str(value)
    if len(text) <= keep:
        return REDACTED
    return f"{REDACTED}\u2026{text[-keep:]}"


@dataclass(slots=True)
class Redactor:
    """Applies redaction rules according to the configured detail level."""

    level: DetailLevel = DetailLevel.STANDARD
    keep_raw: bool = False
    extra_secrets: tuple[str, ...] = ()

    # ── Text ────────────────────────────────────────────────────────────────────

    def text(self, value: Any) -> str:
        """Redact secrets, emails, internal IPs and local paths inside a string."""
        out = str(value)

        for secret in self.extra_secrets:
            if secret and len(str(secret)) >= 4:
                out = out.replace(str(secret), REDACTED)

        for pattern, replacement in _PATTERNS:
            out = pattern.sub(replacement, out)

        if self.level is not DetailLevel.DETAILED:
            out = _EMAIL_RE.sub(REDACTED, out)

        out = _IPV4_RE.sub(lambda m: REDACTED if _is_internal_ip(m.group(0)) else m.group(0), out)
        out = _HOME_RE.sub(lambda m: f"\u2026{os.sep}{m.group(1)}", out)
        return out

    def path(self, value: str) -> str:
        """Return a path safe for display: file name only, never the full path."""
        return os.path.basename(str(value)) or REDACTED

    # ── Structures ──────────────────────────────────────────────────────────────

    def key_is_sensitive(self, key: str) -> bool:
        k = str(key).lower()
        return any(part in k for part in SENSITIVE_KEY_PARTS)

    def key_is_pii(self, key: str) -> bool:
        k = str(key).lower()
        return any(part in k for part in PII_KEY_PARTS)

    def key_is_raw(self, key: str) -> bool:
        k = str(key).lower()
        return any(part in k for part in RAW_KEY_PARTS)

    def data(self, value: Any, _depth: int = 0) -> Any:
        """Recursively redact a findings structure."""
        if _depth > 12:
            return REDACTED

        if isinstance(value, Mapping):
            out: dict[str, Any] = {}
            for raw_key, raw_val in value.items():
                key = str(raw_key)
                if self.key_is_sensitive(key):
                    out[key] = REDACTED
                    continue
                if self.key_is_raw(key) and not self.keep_raw:
                    out[key] = "[OMITTED: raw payload capture disabled]"
                    continue
                if self.key_is_pii(key) and self.level is not DetailLevel.DETAILED:
                    out[key] = REDACTED
                    continue
                out[key] = self.data(raw_val, _depth + 1)
            return out

        if isinstance(value, str):
            return self.text(value)

        if isinstance(value, (list, tuple, set)) or (
            isinstance(value, Iterable) and not isinstance(value, (bytes, bytearray))
        ):
            items = [self.data(v, _depth + 1) for v in value]
            return items if not isinstance(value, tuple) else tuple(items)

        return value

    # ── Exceptions ──────────────────────────────────────────────────────────────

    def exception(self, exc: BaseException) -> str:
        """Render an exception without stack traces, paths or secrets."""
        message = self.text(str(exc)).strip()
        if len(message) > 200:
            message = message[:200] + "\u2026"
        return f"{type(exc).__name__}: {message}" if message else type(exc).__name__


DEFAULT_REDACTOR = Redactor()


def redact_text(value: Any) -> str:
    return DEFAULT_REDACTOR.text(value)


def redact_data(value: Any) -> Any:
    return DEFAULT_REDACTOR.data(value)


def safe_error(exc: BaseException) -> str:
    return DEFAULT_REDACTOR.exception(exc)

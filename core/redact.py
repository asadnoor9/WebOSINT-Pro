"""
WebOSINT Pro - Report redaction.

When ``--redact`` is enabled, generated reports are scrubbed of
PII-adjacent operator context that has no place in a shareable artifact:

  * the operator's local OS username
  * absolute filesystem paths (home directories, temp paths, Windows paths)
  * private / internal IP addresses (RFC 1918, loopback, link-local, CGNAT)

The scan *target* is intentionally preserved -- redaction is about the
operator's environment, not the subject of the (authorized) assessment.
"""

from __future__ import annotations

import getpass
import ipaddress
import os
import re
from typing import Any

_USER_TOKEN = "[redacted-user]"
_PATH_TOKEN = "[redacted-path]"
_IP_TOKEN = "[redacted-ip]"

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# Path terminators: whitespace, quotes, and common punctuation/delimiters.
_PATH_STOP = r'[^\s"\':,)]+'
# Unix absolute paths under common home roots, and Windows user paths.
_UNIX_HOME_RE = re.compile(r"/(?:home|Users|root)/" + _PATH_STOP)
_WIN_HOME_RE = re.compile(r"[A-Za-z]:\\\\?Users\\\\?" + _PATH_STOP, re.IGNORECASE)
_TMP_RE = re.compile(r"/tmp/" + _PATH_STOP)


def _current_user() -> str | None:
    try:
        return getpass.getuser()
    except Exception:  # pragma: no cover - environment dependent
        return os.environ.get("USER") or os.environ.get("USERNAME")


def _is_private_ip(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved


def redact_text(text: str) -> str:
    if not text:
        return text
    result = text
    user = _current_user()
    if user and len(user) >= 3:
        result = re.sub(rf"\b{re.escape(user)}\b", _USER_TOKEN, result)
    result = _WIN_HOME_RE.sub(_PATH_TOKEN, result)
    result = _UNIX_HOME_RE.sub(_PATH_TOKEN, result)
    result = _TMP_RE.sub(_PATH_TOKEN, result)
    result = _IPV4_RE.sub(
        lambda m: _IP_TOKEN if _is_private_ip(m.group(0)) else m.group(0),
        result,
    )
    return result


def redact_obj(obj: Any) -> Any:
    """Recursively redact strings inside a JSON-like structure."""
    if isinstance(obj, str):
        return redact_text(obj)
    if isinstance(obj, dict):
        return {
            (redact_text(k) if isinstance(k, str) else k): redact_obj(v) for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [redact_obj(v) for v in obj]
    if isinstance(obj, tuple):
        return tuple(redact_obj(v) for v in obj)
    return obj

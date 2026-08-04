"""Tests for the offline JWT inspection logic."""

import base64
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from modules.api_module import Module as APIModule  # noqa: E402


class _Cfg:
    target = "example.com"
    dry_run = True
    user_agent = "test"
    timeout = 5
    response_cache = None
    proxy = None
    delay = 0
    retries = 0


class _Log:
    def __getattr__(self, name):
        return lambda *a, **k: None


def _mk(header, payload):
    def enc(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")
    return enc(header) + "." + enc(payload) + ".sig"


def _module():
    return APIModule(_Cfg(), _Log(), None)


def test_is_jwt():
    m = _module()
    assert m._is_jwt(_mk({"alg": "HS256"}, {"sub": "1"})) is True
    assert m._is_jwt("not.a.jwt") is False
    assert m._is_jwt("plainstring") is False


def test_alg_none_is_critical():
    m = _module()
    issues = m._check_jwt_issues(m._decode_jwt(_mk({"alg": "none"}, {"sub": "1"})))
    assert any("alg=none" in i for i in issues)


def test_symmetric_alg_flagged():
    m = _module()
    issues = m._check_jwt_issues(m._decode_jwt(_mk({"alg": "HS256"}, {"sub": "1"})))
    assert any("Symmetric" in i for i in issues)


def test_expired_token_flagged():
    m = _module()
    issues = m._check_jwt_issues(m._decode_jwt(_mk({"alg": "RS256"}, {"exp": int(time.time()) - 100})))
    assert any("expired" in i.lower() for i in issues)


def test_decode_bad_token():
    m = _module()
    assert "error" in m._decode_jwt("only.two")

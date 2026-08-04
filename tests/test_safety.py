"""Tests for the fail-closed safety gate."""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from core.safety import SafetyController  # noqa: E402


def _ctrl(open_target=False, scope_file=None):
    ctrl = SafetyController(open_target=open_target, scope_file=scope_file)
    ctrl._allowlist = []
    return ctrl


@pytest.mark.parametrize(
    "authorized,open_target,expected",
    [
        (False, False, False),
        (False, True, False),
        (True, False, False),
        (True, True, True),
    ],
)
def test_gate_matrix(authorized, open_target, expected):
    ctrl = _ctrl(open_target=open_target)
    assert ctrl.validate("example.com", authorized=authorized).allowed is expected


def test_unauthorized_always_refused_even_with_open_target():
    ctrl = _ctrl(open_target=True)
    result = ctrl.validate("example.com", authorized=False)
    assert result.allowed is False
    assert any("Authorization" in e for e in result.errors)


def test_target_classification_private():
    ctrl = _ctrl(open_target=True)
    result = ctrl.validate("192.168.1.10", authorized=True)
    assert result.is_private is True
    assert result.target_type == "private"


def test_target_classification_localhost():
    ctrl = _ctrl(open_target=True)
    result = ctrl.validate("localhost", authorized=True)
    assert result.is_localhost is True
    assert result.resolved_ips == ["127.0.0.1"]


def test_scope_file_fail_closed(tmp_path):
    scope = tmp_path / "scope.txt"
    scope.write_text("in-scope.example.com\n10.0.0.0/24\n")
    ctrl = SafetyController(scope_file=str(scope))
    ctrl._allowlist = []
    assert ctrl.validate("in-scope.example.com", authorized=True).allowed is True
    assert ctrl.validate("api.in-scope.example.com", authorized=True).allowed is True
    assert ctrl.validate("not-in-scope.example.com", authorized=True).allowed is False
    assert ctrl.validate("10.0.0.5", authorized=True).allowed is True

"""Authorization gate: nothing may touch the network without explicit consent."""

import pytest

from core.safety import AuthorizationError, SafetyController, SafetyPolicy


def test_default_policy_is_unauthorized_and_passive():
    policy = SafetyPolicy()
    assert policy.authorized is False
    assert policy.active is False
    assert policy.passive_only is True


def test_require_authorized_raises_without_consent():
    policy = SafetyPolicy(authorized=False)
    with pytest.raises(AuthorizationError):
        policy.require_authorized()


def test_require_authorized_raises_without_target_confirmation():
    policy = SafetyPolicy(authorized=True, confirmed=False)
    with pytest.raises(AuthorizationError):
        policy.require_authorized()


def test_authorized_and_confirmed_passes():
    policy = SafetyPolicy(authorized=True, confirmed=True)
    policy.require_authorized()


def test_active_checks_blocked_in_passive_mode():
    policy = SafetyPolicy(authorized=True, confirmed=True, active=False)
    with pytest.raises(AuthorizationError):
        policy.require_active("port scan")


def test_active_checks_allowed_with_opt_in():
    policy = SafetyPolicy(authorized=True, confirmed=True, active=True)
    policy.require_active("port scan")


def test_validate_refuses_unauthorized_target():
    controller = SafetyController(SafetyPolicy(authorized=False))
    result = controller.validate("example.com")
    assert result.allowed is False
    assert any("authoriz" in e.lower() for e in result.errors)


def test_validate_allows_public_domain_when_authorized():
    controller = SafetyController(SafetyPolicy(authorized=True, confirmed=True))
    result = controller.validate("example.com")
    assert result.allowed is True


def test_confirm_interactive_requires_exact_target(monkeypatch):
    controller = SafetyController(SafetyPolicy(authorized=True))
    monkeypatch.setattr("builtins.input", lambda *_: "wrong-target.com")
    assert controller.confirm_interactive("example.com") is False
    monkeypatch.setattr("builtins.input", lambda *_: "example.com")
    assert controller.confirm_interactive("example.com") is True

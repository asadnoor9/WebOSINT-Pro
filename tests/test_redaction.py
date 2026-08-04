"""Redaction: secrets, PII, internal IPs and local paths must never leak."""

from core.redaction import REDACTED, DetailLevel, Redactor, safe_error


def test_bearer_token_is_redacted():
    text = "Authorization: Bearer abcdef1234567890abcdef1234567890"
    assert "abcdef1234567890" not in Redactor().text(text)


def test_api_key_assignment_is_redacted():
    out = Redactor().text("shodan_api_key=SUPERSECRETVALUE12345")
    assert "SUPERSECRETVALUE12345" not in out
    assert REDACTED in out


def test_extra_secrets_are_redacted_verbatim():
    redactor = Redactor(extra_secrets=("my-live-shodan-key",))
    assert "my-live-shodan-key" not in redactor.text("key is my-live-shodan-key ok")


def test_local_paths_are_reduced_to_basenames():
    out = Redactor().path("/home/analyst/projects/webosint-pro/reports/scan.json")
    assert "/home/analyst" not in out
    assert out.endswith("scan.json")


def test_internal_ips_are_redacted():
    out = Redactor().text("internal host 192.168.1.20 responded")
    assert "192.168.1.20" not in out


def test_public_ips_are_preserved():
    assert "93.184.216.34" in Redactor().text("resolved to 93.184.216.34")


def test_sensitive_dict_keys_are_masked():
    data = {
        "api_key": "livekey123456",
        "cookie": "session=abc",
        "password": "hunter2",
        "status_code": 200,
    }
    out = Redactor().data(data)
    assert out["api_key"] == REDACTED
    assert out["cookie"] == REDACTED
    assert out["password"] == REDACTED
    assert out["status_code"] == 200


def test_minimal_detail_drops_emails_and_pii():
    data = {"emails": ["person@example.com"], "host": "example.com"}
    out = Redactor(level=DetailLevel.MINIMAL).data(data)
    assert "person@example.com" not in str(out)
    assert out["host"] == "example.com"


def test_raw_payloads_dropped_unless_enabled():
    data = {"raw_response": "<html>secret</html>", "headers": {"Cookie": "a=b"}}
    assert "secret" not in str(Redactor(keep_raw=False).data(data))


def test_exception_message_has_no_traceback_or_path():
    message = ""
    try:
        open("/home/analyst/.secrets/token.txt")
    except OSError as exc:
        message = Redactor().exception(exc)
    assert "/home/analyst" not in message
    assert "Traceback" not in message


def test_safe_error_helper_masks_secrets():
    message = safe_error(ValueError("failed with api_key=ABCDEF1234567890"))
    assert "ABCDEF1234567890" not in message

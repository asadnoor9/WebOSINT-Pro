from reports.markdown_report import MarkdownReport


def test_markdown_report_renders_basic_scan(tmp_path):
    path = tmp_path / "report.md"
    results = {
        "meta": {"target": "example.com", "profile": "safe", "session_id": "abc123"},
        "summary": {"total_findings": 1, "risk_counts": {"medium": 1}},
        "findings": {"http": {"missing_security_headers": ["content-security-policy"]}},
        "errors": {},
    }

    MarkdownReport(results).save(str(path))

    content = path.read_text(encoding="utf-8")
    assert "WebOSINT Pro Report" in content
    assert "example.com" in content
    assert "missing_security_headers" in content

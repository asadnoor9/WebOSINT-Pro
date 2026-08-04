from ai.analysis import FindingAnalyzer


def test_finding_analyzer_scores_high_signal_findings():
    result = FindingAnalyzer().analyze(
        {
            "summary": {"risk_counts": {"critical": 1, "high": 0, "medium": 0}},
            "findings": {"javascript": {"secrets": [{"type": "token"}]}},
        }
    )

    assert result.priority == "critical"
    assert result.score == 100
    assert result.attack_paths

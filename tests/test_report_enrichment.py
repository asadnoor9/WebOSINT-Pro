from reporting.enrichment import build_path_evidence, enrich_results


def test_path_evidence_categorizes_sensitive_paths():
    rows = build_path_evidence(
        {
            "sensitive": [
                {
                    "path": "/.env",
                    "url": "https://example.com/.env",
                    "status": 200,
                    "content_type": "text/plain",
                    "response_size": 120,
                },
                {
                    "path": "/.env",
                    "url": "https://example.com/.env",
                    "status": 200,
                },
            ]
        }
    )

    assert len(rows) == 1
    assert rows[0]["category"] == "environment_secret"
    assert "CWE-798" in rows[0]["cwe"]
    assert rows[0]["confidence"] == "high"


def test_enrichment_builds_remediation_and_siem_sections():
    enriched = enrich_results(
        {
            "findings": {
                "dirs": {
                    "sensitive": [
                        {
                            "path": "/.git/config",
                            "url": "https://example.com/.git/config",
                            "status": 403,
                        }
                    ],
                    "_risk_sensitive_paths": "critical",
                },
                "siem": {
                    "detected": [
                        {
                            "service_name": "Kibana",
                            "port": 5601,
                            "url": "https://example.com:5601/",
                        }
                    ],
                    "_risk_siem_exposed": "high",
                },
            }
        }
    )

    assert enriched["remediation_intelligence"]
    assert enriched["path_evidence"][0]["category"] == "vcs_metadata"
    assert enriched["soc_siem_exposure"][0]["service_name"] == "Kibana"
    assert enriched["cwe_cve_mapping"]

"""Report enrichment and remediation intelligence helpers."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass(slots=True)
class Mapping:
    cwe: list[str]
    cve: list[str] = field(default_factory=list)
    note: str = "No direct CVE mapped; CWE-only classification"


@dataclass(slots=True)
class RemediationItem:
    issue_title: str
    module: str
    severity: str
    confidence: str
    affected: list[str]
    evidence: list[dict[str, Any]]
    why_risky: str
    impact: str
    cwe: list[str]
    cve: list[str]
    cve_note: str
    recommended_fix: str
    next_actions: list[str]


PATH_CATEGORY_RULES = [
    (
        "environment_secret",
        (".env",),
        "Environment or dotenv file",
        "May disclose credentials, API keys, database DSNs, mail secrets, or cloud tokens.",
        Mapping(["CWE-200", "CWE-538", "CWE-798", "CWE-522"]),
        "Remove the file from the web root, rotate exposed secrets, and block dotfiles at the edge/web server.",
        "critical",
    ),
    (
        "vcs_metadata",
        (".git", ".svn"),
        "Version-control metadata",
        "May disclose source code, commit history, configuration, branches, and credentials committed by mistake.",
        Mapping(["CWE-200", "CWE-552", "CWE-538"]),
        "Deny access to VCS directories and verify source metadata is not deployed to public web roots.",
        "critical",
    ),
    (
        "backup_file",
        (".bak", ".backup", ".old", ".sql", ".tar", ".gz", ".zip", "~", "backup", "dump"),
        "Backup or database dump",
        "Backup artifacts can expose application source, user data, database records, and historical secrets.",
        Mapping(["CWE-530", "CWE-200", "CWE-538"]),
        "Move backups outside the web root, require authenticated storage, and purge public artifacts.",
        "high",
    ),
    (
        "config_file",
        (
            "config",
            "settings",
            "database.yml",
            "secrets.yml",
            "wp-config",
            "composer.json",
            "package.json",
        ),
        "Configuration file",
        "Configuration files often reveal framework details, dependency versions, credentials, and internal paths.",
        Mapping(["CWE-200", "CWE-538", "CWE-552"]),
        "Restrict direct access to configuration files and review deployment packaging rules.",
        "high",
    ),
    (
        "admin_or_debug",
        (
            "admin",
            "debug",
            "__debug__",
            "phpinfo",
            "server-status",
            "server-info",
            "actuator",
            "trace",
        ),
        "Admin, diagnostic, or debug endpoint",
        "Administrative and debug surfaces can expose sensitive runtime data or provide a path to unauthorized access.",
        Mapping(["CWE-200", "CWE-215", "CWE-284", "CWE-489"]),
        "Require strong authentication, remove debug endpoints, and restrict administrative routes by network policy.",
        "high",
    ),
    (
        "storage_uploads",
        ("storage", "uploads", "upload", "files", "media"),
        "Storage or uploads directory",
        "Public storage directories may expose user-uploaded content, private documents, or executable upload paths.",
        Mapping(["CWE-200", "CWE-552", "CWE-434"]),
        "Disable directory listing, enforce object ACLs, and segregate public from private uploads.",
        "medium",
    ),
    (
        "robots_txt",
        ("robots.txt",),
        "Robots.txt disclosure",
        "Robots directives can reveal hidden admin, staging, or sensitive application paths.",
        Mapping(["CWE-200"]),
        "Review robots.txt for sensitive paths and enforce real access controls on disallowed routes.",
        "low",
    ),
    (
        "well_known",
        (".well-known",),
        "Well-known metadata",
        "Well-known paths may reveal security contacts, federation metadata, or validation endpoints.",
        Mapping(["CWE-200"]),
        "Review exposed metadata and remove stale validation or sensitive federation files.",
        "info",
    ),
    (
        "misc_sensitive",
        (".DS_Store", "Thumbs.db", "readme", "CHANGELOG", "INSTALL", "LICENSE"),
        "Metadata or documentation exposure",
        "Metadata and documentation can reveal directory structure, versions, deployment details, and internal notes.",
        Mapping(["CWE-200", "CWE-538"]),
        "Remove nonessential metadata and documentation from production web roots.",
        "medium",
    ),
]


RISK_FLAG_DETAILS = {
    "secrets": (
        "Secrets",
        Mapping(["CWE-798", "CWE-522", "CWE-312", "CWE-200"]),
        "Exposed secrets can enable unauthorized access to APIs, cloud services, or user data.",
        "Rotate the exposed secret, remove it from client-side assets, and add secret scanning to CI.",
    ),
    "exposed_db": (
        "Exposed Db",
        Mapping(["CWE-200", "CWE-284", "CWE-552", "CWE-89"]),
        "Exposed database services can leak data or permit unauthorized administrative access.",
        "Restrict database access to private networks, enforce authentication, and remove public listeners.",
    ),
    "backup_files": (
        "Backup Files",
        Mapping(["CWE-530", "CWE-200", "CWE-538"]),
        "Backup files may disclose source, credentials, and historical production data.",
        "Purge public backups and move retention workflows to authenticated storage.",
    ),
    "missing_headers": (
        "Missing Headers",
        Mapping(["CWE-693", "CWE-1021", "CWE-16"]),
        "Missing browser security headers increase exposure to clickjacking, XSS impact, and content-type confusion.",
        "Add CSP, HSTS, X-Frame-Options/frame-ancestors, Referrer-Policy, and related hardening headers.",
    ),
    "no_dmarc": (
        "No Dmarc",
        Mapping(["CWE-345", "CWE-290"]),
        "Missing DMARC allows spoofed mail to pass without domain-level reporting or enforcement.",
        "Publish a DMARC policy and move from monitoring to quarantine/reject after validation.",
    ),
    "no_dkim": (
        "No Dkim",
        Mapping(["CWE-345", "CWE-347"]),
        "Missing DKIM weakens message integrity and domain authentication.",
        "Enable DKIM signing for all outbound mail sources and rotate selectors regularly.",
    ),
    "no_spf": (
        "No Spf",
        Mapping(["CWE-345", "CWE-290"]),
        "Missing SPF makes it easier for unauthorized senders to impersonate the domain.",
        "Publish a least-privilege SPF record covering all authorized outbound mail providers.",
    ),
    "email_spoofing": (
        "Email Spoofing",
        Mapping(["CWE-345", "CWE-290"]),
        "Weak mail authentication can support phishing, brand impersonation, and BEC campaigns.",
        "Harden SPF, DKIM, and DMARC alignment and monitor authentication failures.",
    ),
    "header_disclosure": (
        "Server Version Disclosure",
        Mapping(["CWE-200"]),
        "Version and framework disclosures help attackers select targeted exploits.",
        "Suppress verbose server/framework headers and keep exposed services patched.",
    ),
    "siem_exposed": (
        "SOC/SIEM Exposure",
        Mapping(["CWE-200", "CWE-284", "CWE-552"]),
        "Public SOC dashboards may leak telemetry, alert data, infrastructure names, and operational context.",
        "Restrict dashboards to VPN/private networks and enforce SSO/MFA with least privilege.",
    ),
    "open_ports": (
        "Open Administrative Services",
        Mapping(["CWE-200", "CWE-284"]),
        "Administrative or database ports exposed to the internet increase attack surface and brute-force risk.",
        "Restrict services by firewall, bind to private interfaces, and require strong authentication.",
    ),
}


def enrich_results(results: dict[str, Any]) -> dict[str, Any]:
    """Return structured enrichment sections derived from raw module results."""
    findings = results.get("findings", {})
    path_evidence = build_path_evidence(findings.get("dirs", {}))
    remediation = build_remediation_intelligence(findings, path_evidence)
    return {
        "remediation_intelligence": [asdict(item) for item in remediation],
        "path_evidence": path_evidence,
        "cwe_cve_mapping": build_mapping_table(remediation),
        "soc_siem_exposure": normalize_siem(findings.get("siem", {})),
        "port_service_intelligence": normalize_ports(
            findings.get("ports", {}), findings.get("http", {})
        ),
        "subdomains_and_web_pages": normalize_web_assets(findings),
        "authentication_detection": normalize_authentication(findings),
        "traceroute_hop_analysis": normalize_traceroute(findings.get("ports", {})),
    }


def build_path_evidence(dirs_data: dict[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(dirs_data, dict):
        return []
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for item in dirs_data.get("sensitive", []) + dirs_data.get("backup_files", []):
        if not isinstance(item, dict):
            continue
        path = str(item.get("path", ""))
        url = str(item.get("url", ""))
        key = (path, url)
        if key in seen:
            continue
        seen.add(key)
        category = categorize_path(path)
        rows.append(
            {
                **item,
                "risk_class": category["risk_class"],
                "category": category["category"],
                "category_title": category["title"],
                "explanation": category["why"],
                "cwe": category["mapping"].cwe,
                "cve": category["mapping"].cve,
                "cve_note": category["mapping"].note,
                "recommended_fix": category["fix"],
                "confidence": confidence_for_status(item.get("status")),
            }
        )
    return sorted(
        rows, key=lambda row: (SEVERITY_ORDER.get(row["risk_class"], 9), row.get("path", ""))
    )


def categorize_path(path: str) -> dict[str, Any]:
    lowered = path.lower()
    for category, needles, title, why, mapping, fix, risk_class in PATH_CATEGORY_RULES:
        if any(needle.lower() in lowered for needle in needles):
            return {
                "category": category,
                "title": title,
                "why": why,
                "mapping": mapping,
                "fix": fix,
                "risk_class": risk_class,
            }
    return {
        "category": "unknown_sensitive",
        "title": "Sensitive or unusual path",
        "why": "The path responded in a way that suggests it may expose nonstandard application surface.",
        "mapping": Mapping(["CWE-200"]),
        "fix": "Validate whether this path is intentional and restrict access when not required.",
        "risk_class": "medium",
    }


def confidence_for_status(status: Any) -> str:
    if status in (200, 201, 204):
        return "high"
    if status in (301, 302, 307, 308, 401, 403):
        return "medium"
    return "low"


def build_remediation_intelligence(
    findings: dict[str, Any],
    path_evidence: list[dict[str, Any]],
) -> list[RemediationItem]:
    items: list[RemediationItem] = []
    if path_evidence:
        for category in sorted({row["category"] for row in path_evidence}):
            rows = [row for row in path_evidence if row["category"] == category]
            first = rows[0]
            affected = [str(row.get("url") or row.get("path")) for row in rows]
            items.append(
                RemediationItem(
                    issue_title=f"Sensitive Paths: {first['category_title']}",
                    module="dirs",
                    severity=max_severity(row["risk_class"] for row in rows),
                    confidence=max_confidence(row["confidence"] for row in rows),
                    affected=affected,
                    evidence=rows,
                    why_risky=first["explanation"],
                    impact=first["explanation"],
                    cwe=first["cwe"],
                    cve=first["cve"],
                    cve_note=first["cve_note"],
                    recommended_fix=first["recommended_fix"],
                    next_actions=[
                        "Validate whether each URL is reachable without authentication.",
                        "Remove public access and retest for 200/redirect/403 behavior.",
                        "Rotate any secrets if file contents may have been exposed.",
                    ],
                )
            )

    for module, data in findings.items():
        if not isinstance(data, dict):
            continue
        for key, severity in data.items():
            key = str(key)
            if not key.startswith("_risk") or key == "_risk_sensitive_paths":
                continue
            risk_name = key[6:]
            title, mapping, why, fix = RISK_FLAG_DETAILS.get(
                risk_name,
                (
                    risk_name.replace("_", " ").title(),
                    Mapping(["CWE-200"]),
                    "The finding may expose sensitive information or increase attack surface.",
                    "Review the finding, validate exposure, and apply least-privilege access controls.",
                ),
            )
            evidence = extract_evidence(module, risk_name, data)
            items.append(
                RemediationItem(
                    issue_title=title,
                    module=module,
                    severity=normalize_severity(str(severity)),
                    confidence="medium",
                    affected=extract_affected(evidence),
                    evidence=evidence,
                    why_risky=why,
                    impact=why,
                    cwe=mapping.cwe,
                    cve=mapping.cve,
                    cve_note=mapping.note,
                    recommended_fix=fix,
                    next_actions=[
                        "Validate the finding manually against the target scope.",
                        "Prioritize fixes for internet-exposed and unauthenticated assets.",
                        "Retest after remediation and preserve evidence for the report.",
                    ],
                )
            )

    return dedupe_remediation(items)


def extract_evidence(module: str, risk_name: str, data: dict[str, Any]) -> list[dict[str, Any]]:
    candidates = {
        "secrets": ["secrets", "inline_secrets"],
        "exposed_db": ["exposed", "databases", "services"],
        "backup_files": ["backup_files"],
        "missing_headers": ["missing_security_headers"],
        "no_dmarc": ["dmarc"],
        "no_dkim": ["dkim"],
        "no_spf": ["spf"],
        "email_spoofing": ["email_spoofing_risk", "spf", "dmarc", "dkim"],
        "header_disclosure": ["info_disclosure_headers", "server"],
        "siem_exposed": ["detected"],
        "open_ports": ["dangerous_ports", "ports"],
    }.get(risk_name, [])
    evidence: list[dict[str, Any]] = []
    for field_name in candidates:
        value = data.get(field_name)
        if value in (None, "", [], {}):
            continue
        if isinstance(value, list):
            for item in value[:100]:
                evidence.append(item if isinstance(item, dict) else {"value": item})
        elif isinstance(value, dict):
            evidence.append({"field": field_name, **value})
        else:
            evidence.append({"field": field_name, "value": value})
    if not evidence:
        evidence.append({"module": module, "risk": risk_name})
    return evidence


def extract_affected(evidence: list[dict[str, Any]]) -> list[str]:
    affected: list[str] = []
    for row in evidence:
        for key in ("url", "host", "path", "source", "matched", "value", "port"):
            value = row.get(key)
            if value not in (None, "", [], {}):
                affected.append(str(value))
                break
    return sorted(set(affected))


def dedupe_remediation(items: list[RemediationItem]) -> list[RemediationItem]:
    deduped: dict[tuple[str, str], RemediationItem] = {}
    for item in items:
        key = (item.module, item.issue_title.lower())
        existing = deduped.get(key)
        if existing is None:
            deduped[key] = item
            continue
        existing.affected = sorted(set(existing.affected + item.affected))
        existing.evidence = dedupe_dicts(existing.evidence + item.evidence)
        existing.severity = max_severity([existing.severity, item.severity])
    return sorted(deduped.values(), key=lambda item: SEVERITY_ORDER.get(item.severity, 9))


def build_mapping_table(items: list[RemediationItem]) -> list[dict[str, Any]]:
    rows = []
    seen = set()
    for item in items:
        key = (item.issue_title, tuple(item.cwe), tuple(item.cve))
        if key in seen:
            continue
        seen.add(key)
        rows.append(
            {
                "issue": item.issue_title,
                "module": item.module,
                "severity": item.severity,
                "cwe": item.cwe,
                "cve": item.cve,
                "cve_note": item.cve_note,
            }
        )
    return rows


def normalize_siem(siem_data: dict[str, Any]) -> list[dict[str, Any]]:
    return dedupe_dicts(siem_data.get("detected", [])) if isinstance(siem_data, dict) else []


def normalize_ports(ports_data: dict[str, Any], http_data: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(ports_data, dict):
        return {}
    cdn = http_data.get("cdn") if isinstance(http_data, dict) else []
    return {
        "scanner": ports_data.get("scanner"),
        "host_discovery": ports_data.get("host_discovery", {}),
        "state_breakdown": ports_data.get("state_breakdown", {}),
        "open_ports": ports_data.get("ports", {}),
        "dangerous_ports": ports_data.get("dangerous_ports", []),
        "os_guess": ports_data.get("os_guess", []),
        "latency": ports_data.get("latency", ""),
        "cdn_or_proxy_note": (
            f"Host appears fronted by CDN/proxy signals: {', '.join(cdn)}" if cdn else ""
        ),
    }


def normalize_web_assets(findings: dict[str, Any]) -> dict[str, Any]:
    subdomains = (
        findings.get("subdomains", {}) if isinstance(findings.get("subdomains"), dict) else {}
    )
    webapp = findings.get("webapp", {}) if isinstance(findings.get("webapp"), dict) else {}
    return {
        "subdomains": subdomains.get("all_subdomains", []),
        "live_hosts": subdomains.get("live_hosts", []),
        "pages": webapp.get("pages", []),
        "sitemap_urls": webapp.get("sitemap", {}).get("urls", []),
        "robots_disallowed": webapp.get("robots_txt", {}).get("disallowed", []),
    }


def normalize_authentication(findings: dict[str, Any]) -> list[dict[str, Any]]:
    auth_rows = []
    for source in ("subdomains", "webapp"):
        data = findings.get(source, {})
        if not isinstance(data, dict):
            continue
        for row in data.get("live_hosts", []) + data.get("pages", []):
            if isinstance(row, dict) and row.get("auth_type"):
                auth_rows.append({"module": source, **row})
    return dedupe_dicts(auth_rows)


def normalize_traceroute(ports_data: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(ports_data, dict):
        return {}
    trace = ports_data.get("traceroute", [])
    return {
        "hop_count": len(trace),
        "hops": trace,
        "latency": ports_data.get("latency", ""),
    }


def dedupe_dicts(rows: list[Any]) -> list[dict[str, Any]]:
    output = []
    seen = set()
    for row in rows:
        if not isinstance(row, dict):
            row = {"value": row}
        marker = tuple(sorted((str(k), str(v)) for k, v in row.items()))
        if marker in seen:
            continue
        seen.add(marker)
        output.append(row)
    return output


def normalize_severity(value: str) -> str:
    lowered = value.lower()
    return lowered if lowered in SEVERITY_ORDER else "info"


def max_severity(values: Any) -> str:
    vals = [normalize_severity(str(v)) for v in values]
    return min(vals, key=lambda val: SEVERITY_ORDER.get(val, 9), default="info")


def max_confidence(values: Any) -> str:
    order = {"high": 0, "medium": 1, "low": 2}
    vals = [str(v).lower() for v in values]
    return min(vals, key=lambda val: order.get(val, 9), default="medium")

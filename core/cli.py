"""
WebOSINT Pro - CLI argument parsing

Separated from the runtime entry point so the parser can be unit tested
without importing the whole scan stack.
"""

from __future__ import annotations

import argparse

MODULE_HELP: dict[str, str] = {
    "dns": "DNS records: A, AAAA, MX, NS, TXT, SOA, CNAME, SRV, DNSSEC (passive)",
    "ip": "IP intelligence: ASN, ISP, geo, reputation (passive)",
    "whois": "WHOIS: registrar, dates (registrant PII redacted unless --detail detailed)",
    "subdomains": "Subdomain enumeration via certificate transparency (passive)",
    "http": "HTTP headers, security headers, server + CDN detection (passive)",
    "ssl": "TLS certificate parsing, expiry, protocol support (passive)",
    "mail": "Mail security: MX, SPF, DKIM, DMARC (passive)",
    "webapp": "robots.txt, sitemap, technology fingerprinting (passive)",
    "javascript": "JavaScript endpoint extraction and secret pattern detection (passive)",
    "cve": "CVE/CWE mapping for detected versions (passive, offline-first)",
    "osint": "Public OSINT sources (passive; API keys optional)",
    "ports": "Port scanning via nmap (ACTIVE)",
    "dirs": "Directory and endpoint brute force (ACTIVE)",
    "api": "API surface probing: JWT, GraphQL, endpoint mapping (ACTIVE)",
    "websocket": "WebSocket endpoint detection (ACTIVE)",
    "database": "Exposed database service detection (ACTIVE)",
    "waf": "WAF/firewall detection through behavioural probes (ACTIVE)",
    "ids": "IDS/IPS inference from response patterns (ACTIVE)",
    "siem": "Exposed SIEM dashboard detection (ACTIVE)",
    "honeypot": "Honeypot and decoy detection (ACTIVE)",
}

EPILOG = """
Authorized use only
  Every run requires --authorized and --confirm-target <target>.
  Passive OSINT is the default. Intrusive checks need --active.

Examples
  webosint -t example.com --authorized --confirm-target example.com
  webosint -t example.com --authorized --confirm-target example.com --json
  webosint -t example.com --authorized --confirm-target example.com \\
           --modules dns,whois,ssl --detail minimal
  webosint -t example.com --authorized --confirm-target example.com \\
           --active --allowlist configs/allowlist.json -v
  webosint --list-modules
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webosint",
        description=(
            "WebOSINT Pro - passive-by-default web OSINT and reconnaissance framework "
            "for authorized security testing."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=EPILOG,
    )

    # ── Target ───────────────────────────────────────────────────────────────
    target = parser.add_argument_group("target")
    target.add_argument("-t", "--target", help="Target domain or IP you are authorized to test")
    target.add_argument(
        "--confirm-target",
        metavar="TARGET",
        help="Retype the target exactly to confirm authorization (non-interactive runs)",
    )

    # ── Authorization & safety ─────────────────────────────────────────────────
    safety = parser.add_argument_group("authorization and safety")
    safety.add_argument(
        "--authorized",
        action="store_true",
        help="Required. Asserts you have explicit written permission to test the target",
    )
    safety.add_argument(
        "--active",
        action="store_true",
        help="Enable ACTIVE/intrusive checks (port scans, brute force, payload probes)",
    )
    safety.add_argument(
        "--allowlist",
        metavar="PATH",
        help="JSON file of approved targets/CIDRs; scans outside it are refused",
    )
    safety.add_argument(
        "--allow-private",
        action="store_true",
        help="Permit localhost/private/reserved ranges (owned lab systems only)",
    )
    safety.add_argument(
        "--insecure-tls-i-accept-the-risk",
        dest="insecure_tls",
        action="store_true",
        help="Disable TLS certificate verification; all results are marked UNTRUSTED",
    )
    safety.add_argument(
        "--max-redirects",
        type=int,
        default=3,
        help="Maximum redirect hops, each re-validated against the policy (default: 3)",
    )

    # ── Modules ──────────────────────────────────────────────────────────────
    modules = parser.add_argument_group("modules")
    modules.add_argument("--modules", default="all", help='Comma-separated modules or "all"')
    modules.add_argument("--skip-modules", default="", help="Comma-separated modules to skip")
    modules.add_argument("--list-modules", action="store_true", help="List modules and exit")
    modules.add_argument(
        "--profile",
        choices=["safe", "medium", "aggressive", "stealth", "bugbounty", "api-only"],
        default="safe",
        help="Scan profile (default: safe / passive)",
    )
    modules.add_argument("--mode", help=argparse.SUPPRESS)  # backward-compatible alias

    # ── Privacy ──────────────────────────────────────────────────────────────
    privacy = parser.add_argument_group("privacy")
    privacy.add_argument(
        "--detail",
        choices=["minimal", "standard", "detailed"],
        default="standard",
        help="Data minimization level (default: standard)",
    )
    privacy.add_argument(
        "--keep-raw",
        action="store_true",
        help="Persist raw HTTP bodies/headers (off by default)",
    )
    privacy.add_argument(
        "--retention-days",
        type=int,
        default=30,
        help="Delete generated reports older than N days (0 disables, default: 30)",
    )
    privacy.add_argument(
        "--log-retention-days",
        type=int,
        default=14,
        help="Delete log files older than N days (0 disables, default: 14)",
    )
    privacy.add_argument(
        "--no-cleanup", action="store_true", help="Skip the retention cleanup pass"
    )
    privacy.add_argument(
        "--telemetry",
        action="store_true",
        help="Reserved flag; telemetry is disabled and never sends data",
    )

    # ── Output ───────────────────────────────────────────────────────────────
    output = parser.add_argument_group("output")
    output.add_argument(
        "--output",
        choices=[
            "json",
            "html",
            "markdown",
            "csv",
            "docx",
            "pdf",
            "both",
            "all",
            "none",
        ],
        default="json",
        help="Report format written to disk (default: json)",
    )
    output.add_argument("--output-dir", default="reports", help="Report output directory")
    output.add_argument("--report-name", help="Custom report filename prefix")
    output.add_argument(
        "--json",
        dest="json_stdout",
        action="store_true",
        help="Emit machine-readable JSON on stdout (implies --quiet)",
    )
    output.add_argument("--no-color", action="store_true", help="Disable colored output")

    # ── Verbosity ────────────────────────────────────────────────────────────
    logging_group = parser.add_argument_group("logging")
    logging_group.add_argument(
        "-q", "--quiet", action="store_true", help="Quiet: errors and final summary only"
    )
    logging_group.add_argument(
        "-v", "--verbose", action="count", default=0, help="Verbose (-v) or debug (-vv)"
    )
    logging_group.add_argument(
        "--log-dir", default="logs", help="Directory for structured log files"
    )
    logging_group.add_argument(
        "--no-log-file", action="store_true", help="Do not write log files to disk"
    )

    # ── Performance ───────────────────────────────────────────────────────────
    perf = parser.add_argument_group("performance")
    perf.add_argument("--threads", type=int, help="Max concurrent modules (default: profile)")
    perf.add_argument("--timeout", type=int, help="Per-request timeout in seconds")
    perf.add_argument("--delay", type=float, help="Delay between requests in seconds")
    perf.add_argument("--retries", type=int, default=2, help="Retry count on failure")
    perf.add_argument("--rate-limit", type=int, help="Max requests per minute")

    # ── Integrations ──────────────────────────────────────────────────────────
    integrations = parser.add_argument_group("integrations")
    integrations.add_argument(
        "--no-external", action="store_true", help="Skip all external tool integrations"
    )
    integrations.add_argument("--config", default="config.json", help="Config file path")
    integrations.add_argument("--proxy", help="HTTP(S) proxy, e.g. http://127.0.0.1:8080")
    integrations.add_argument("--user-agent", help="Custom User-Agent string")
    integrations.add_argument("--wordlist", help="Custom subdomain wordlist path")
    integrations.add_argument("--dir-wordlist", help="Custom directory wordlist path")

    return parser


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    args = build_parser().parse_args(argv)

    # API keys are read from the environment only — never from argv, so they
    # cannot leak through shell history or the process list.
    args.shodan_key = None
    args.nvd_key = None

    if getattr(args, "mode", None):
        args.profile = args.mode
    if args.json_stdout:
        args.quiet = True
    return args

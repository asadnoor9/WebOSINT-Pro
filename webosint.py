#!/usr/bin/env python3
"""
WebOSINT Pro - Production-Grade Web OSINT & Reconnaissance Framework
For authorized security testing only.
"""

import sys
import os
import argparse
import json
import time
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.controller import ScanController
from core.config import Config
from core.logger import setup_logger
from utils.banner import print_banner, print_warning
from utils.output import ColorOutput as C


def parse_args():
    parser = argparse.ArgumentParser(
        prog='webosint',
        description='WebOSINT Pro - Web OSINT & Reconnaissance Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Scan Profiles:
  safe        Passive reconnaissance, minimal noise
  medium      Balanced scanning (default)
  aggressive  Full enumeration, brute force, active probing
  stealth     Slow, randomized, minimal detection footprint

Examples:
  webosint -t example.com
  webosint -t example.com --profile aggressive -v
  webosint -t example.com --modules dns,whois,ssl --output json
  webosint -t example.com --profile stealth --delay 3 -vvv
  webosint -t example.com --shodan-key YOUR_KEY --no-external
        """
    )

    # Target
    parser.add_argument('-t', '--target', required=True, help='Target domain or IP')
    parser.add_argument('--targets-file', help='File with list of targets (one per line)')

    # Profile
    parser.add_argument(
        '--profile', choices=['safe', 'medium', 'aggressive', 'stealth'],
        default='medium', help='Scan profile (default: medium)'
    )

    # Modules
    parser.add_argument(
        '--modules', default='all',
        help='Comma-separated modules or "all" (default: all)'
    )
    parser.add_argument(
        '--skip-modules', default='',
        help='Comma-separated modules to skip'
    )
    parser.add_argument('--list-modules', action='store_true', help='List available modules')

    # Output
    parser.add_argument(
        '--output', choices=['json', 'html', 'both'], default='both',
        help='Report format (default: both)'
    )
    parser.add_argument('--output-dir', default='reports', help='Output directory')
    parser.add_argument('--report-name', help='Custom report filename prefix')

    # Verbosity
    parser.add_argument('-v', '--verbose', action='count', default=0,
                        help='Verbosity: -v, -vv, -vvv')

    # Performance
    parser.add_argument('--threads', type=int, default=10, help='Thread count (default: 10)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout seconds')
    parser.add_argument('--delay', type=float, default=0, help='Delay between requests (seconds)')
    parser.add_argument('--retries', type=int, default=2, help='Retry count on failure')
    parser.add_argument('--rate-limit', type=int, default=50, help='Max requests per minute')

    # Wordlists
    parser.add_argument('--wordlist', help='Custom subdomain wordlist path')
    parser.add_argument('--dir-wordlist', help='Custom directory wordlist path')

    # API Keys
    parser.add_argument('--shodan-key', help='Shodan API key')
    parser.add_argument('--nvd-key', help='NVD API key for CVE lookup')
    parser.add_argument('--config', default='config.json', help='Config file path')

    # Flags
    parser.add_argument('--no-external', action='store_true', help='Skip external tool integrations')
    parser.add_argument('--no-color', action='store_true', help='Disable colored output')
    parser.add_argument('--confirm', action='store_true', help='Skip authorization prompt')
    parser.add_argument('--proxy', help='HTTP proxy (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--user-agent', help='Custom User-Agent string')

    return parser.parse_args()


def list_modules():
    modules = {
        'dns':          'DNS records: A, AAAA, MX, NS, TXT, SOA, CNAME, SRV, DNSSEC, zone transfer',
        'ip':           'IP intelligence: ASN, ISP, geo, reputation, blacklists',
        'whois':        'WHOIS: registrar, owner, creation/expiry dates',
        'subdomains':   'Subdomain enumeration: wordlist + crt.sh + subfinder + amass',
        'http':         'HTTP headers, security headers, server detection, CDN',
        'ssl':          'SSL/TLS: cert parsing, expiry, weak protocols',
        'ports':        'Port scanning via nmap integration',
        'dirs':         'Directory & endpoint discovery, hidden files',
        'webapp':       'Robots.txt, sitemap, web app fingerprinting',
        'javascript':   'JS analysis: endpoint extraction, secret detection',
        'api':          'API security: JWT, GraphQL, endpoint mapping',
        'websocket':    'WebSocket detection (ws:// / wss://)',
        'database':     'Database detection: MySQL, PostgreSQL, MongoDB, Redis, Elastic',
        'mail':         'Mail security: MX, SPF, DKIM, DMARC',
        'waf':          'WAF/firewall detection via wafw00f + behavior analysis',
        'ids':          'IDS/IPS passive inference from response patterns',
        'siem':         'SIEM dashboard detection: Kibana, Splunk, Grafana',
        'honeypot':     'Honeypot & decoy detection: latency, banners, behavior',
        'cve':          'CVE/CWE mapping via NVD API',
        'osint':        'OSINT: theHarvester, Shodan, Google dorks',
    }
    print(f"\n{C.BOLD}{C.CYAN}Available Modules:{C.RESET}\n")
    for name, desc in modules.items():
        print(f"  {C.GREEN}{name:<15}{C.RESET} {desc}")
    print()


def main():
    args = parse_args()

    if args.no_color:
        C.disable()

    print_banner()

    if args.list_modules:
        list_modules()
        sys.exit(0)

    # Authorization warning
    if not args.confirm:
        print_warning(args.target)

    # Load / merge config
    cfg = Config(args)

    # Setup logger
    logger = setup_logger(cfg.verbose, cfg.log_dir)

    logger.info(f"WebOSINT Pro starting | target={args.target} | profile={args.profile}")

    # Run scan
    controller = ScanController(cfg, logger)
    results = controller.run()

    # Summary
    elapsed = results.get('elapsed', 0)
    findings = results.get('total_findings', 0)
    print(f"\n{C.BOLD}{C.GREEN}[✓] Scan complete{C.RESET} | "
          f"Time: {elapsed:.1f}s | Findings: {findings}")

    report_paths = results.get('reports', [])
    for rp in report_paths:
        print(f"    {C.CYAN}→ {rp}{C.RESET}")

    return 0


if __name__ == '__main__':
    sys.exit(main())

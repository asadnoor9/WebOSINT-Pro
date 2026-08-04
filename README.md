<div align="center">

# WebOSINT Pro

**A passive-first Web OSINT, reconnaissance and attack surface management framework for authorized security testing.**

[![CI](https://github.com/asadnoor9/WebOSINT-Pro/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/asadnoor9/WebOSINT-Pro/actions/workflows/ci.yml)
[![CodeQL](https://github.com/asadnoor9/WebOSINT-Pro/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/asadnoor9/WebOSINT-Pro/actions/workflows/codeql.yml)
[![Release](https://img.shields.io/github/v/release/asadnoor9/WebOSINT-Pro?sort=semver&display_name=tag)](https://github.com/asadnoor9/WebOSINT-Pro/releases)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue?logo=python&logoColor=white)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/github/license/asadnoor9/WebOSINT-Pro)](LICENSE)
[![Code style: Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Last commit](https://img.shields.io/github/last-commit/asadnoor9/WebOSINT-Pro)](https://github.com/asadnoor9/WebOSINT-Pro/commits/main)
[![Issues](https://img.shields.io/github/issues/asadnoor9/WebOSINT-Pro)](https://github.com/asadnoor9/WebOSINT-Pro/issues)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

[Installation](docs/INSTALLATION.md) &middot;
[Usage](docs/USAGE.md) &middot;
[Architecture](ARCHITECTURE.md) &middot;
[Troubleshooting](docs/TROUBLESHOOTING.md) &middot;
[Security](SECURITY.md) &middot;
[Contributing](CONTRIBUTING.md)

</div>

---

> [!IMPORTANT]
> **Authorized use only.** WebOSINT Pro refuses to scan any target you have not
> explicitly authorized. Every run requires a written authorization
> acknowledgement, and targets must appear on your allowlist. Scanning systems
> without permission is illegal in most jurisdictions. See
> [SECURITY.md](SECURITY.md).

---

## Table of contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Screenshots](#screenshots)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [Profiles](#profiles)
- [Usage](#usage)
- [Examples](#examples)
- [Output](#output)
- [Reporting](#reporting)
- [Modules](#modules)
- [Integrations](#integrations)
- [Web dashboard](#web-dashboard)
- [Running as a service](#running-as-a-service)
- [Development](#development)
- [Project statistics](#project-statistics)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)
- [Acknowledgements](#acknowledgements)

---

## Overview

WebOSINT Pro maps the public attack surface of a domain you are authorized to
assess, and turns what it finds into reports an operator, a developer and an
executive can each act on.

It is **passive by default**. A default run reads public records — DNS, WHOIS,
certificate transparency, HTTP response metadata, mail policy — and never sends
intrusive traffic. Anything that probes a target more actively (port scanning,
directory discovery, WAF fingerprinting) is gated behind an explicit `--active`
flag, so the safe path is also the default path.

**What makes it different**

| Design decision | Why it matters |
| --- | --- |
| Authorization gate refuses unauthorized targets | Safety is enforced in code, not documented as a suggestion |
| Private, reserved and loopback ranges blocked | Prevents SSRF-style pivoting into internal infrastructure |
| Redaction applied before anything is written | Logs and reports cannot leak credentials, tokens or PII |
| Confidence scoring and source attribution | Every finding states how it was learned and how sure the tool is |
| Deterministic JSON output | Reports diff cleanly, so change detection is trivial |
| Nothing generated is ever committed | All runtime artifacts land in git-ignored `output/` |

---

## Features

**Reconnaissance**

- DNS records, zone posture and DNSSEC state
- WHOIS and registration intelligence
- Subdomain discovery from passive sources
- TLS/SSL certificate inspection and chain validation
- HTTP header, cookie and security-policy analysis
- Technology fingerprinting with confidence scores
- Mail security posture: SPF, DKIM, DMARC, MTA-STS
- Infrastructure attribution: hosting, ASN, ISP, CDN and WAF detection
- Public CVE correlation for identified software versions

**Safety and privacy**

- Mandatory authorization acknowledgement per run
- Allowlist enforcement with fail-closed scope checks
- Private, reserved, loopback and link-local ranges refused
- SSRF-safe redirect handling
- TLS verification on by default, with a deliberately verbose opt-out
- Three detail levels: `minimal`, `standard`, `detailed`
- Redaction of secrets and PII across logs, reports and errors
- No raw HTTP bodies persisted to disk
- Retention policy with automatic cleanup
- Telemetry off, permanently

**Engineering**

- Typed Python throughout, linted and formatted with Ruff
- Plugin architecture with dependency-aware scan planning
- Adaptive concurrency with rate limiting and backoff
- Finding de-duplication and cross-module correlation
- Structured JSON logging
- 240 tests across Python 3.10 – 3.13

---

## Architecture

```
                      ┌──────────────────────────┐
   CLI  ─────────────▶│      engine/cli.py       │
   Web  ─────────────▶│      web/app.py          │
                      └────────────┬─────────────┘
                                   │
                      ┌────────────▼─────────────┐
                      │   core/safety.py         │  authorization, allowlist,
                      │   core/scope.py          │  reserved-range refusal
                      └────────────┬─────────────┘
                                   │  (a refused target stops here)
                      ┌────────────▼─────────────┐
                      │   engine/pipeline.py     │  planning, scheduling,
                      │   engine/selection.py    │  adaptive concurrency
                      └────────────┬─────────────┘
                                   │
            ┌──────────────────────┼──────────────────────┐
            ▼                      ▼                      ▼
     ┌────────────┐         ┌────────────┐         ┌──────────────┐
     │  modules/  │         │ engine/    │         │ integrations/│
     │  21 probes │         │ builtin    │         │ 3rd-party    │
     └──────┬─────┘         └──────┬─────┘         └───────┬──────┘
            └──────────────────────┼───────────────────────┘
                                   ▼
                      ┌──────────────────────────┐
                      │  engine/correlation.py   │  dedupe, confidence,
                      │  engine/confidence.py    │  risk roll-up
                      └────────────┬─────────────┘
                                   ▼
                      ┌──────────────────────────┐
                      │  core/redaction.py       │  redact before write
                      └────────────┬─────────────┘
                                   ▼
                      ┌──────────────────────────┐
                      │  reporting/              │  json html markdown
                      │  reporting/export.py     │  csv  pdf  docx
                      └────────────┬─────────────┘
                                   ▼
                          output/reports/
```

The layering rule is one-directional: `modules/` and `engine/` never import
`reporting/`, and `reporting/` never performs network I/O. Redaction sits
between collection and persistence, so no writer can bypass it.

Full detail lives in [ARCHITECTURE.md](ARCHITECTURE.md).

---

## Screenshots

> Add your own captures to `docs/images/` and reference them here. Placeholder
> images are deliberately omitted so this README never renders a broken image.

| View | Path to add |
| --- | --- |
| CLI scan in progress | `docs/images/cli-scan.png` |
| HTML report | `docs/images/html-report.png` |
| Web dashboard | `docs/images/dashboard.png` |

---

## Installation

**Requirements:** Python 3.10 or newer, Linux/macOS/WSL, and `nmap`, `dnsutils`
and `whois` for the optional active modules.

```bash
# 1. System packages (Debian/Ubuntu/Kali/Parrot)
sudo apt update
sudo apt install -y python3-venv nmap dnsutils whois

# 2. Clone
git clone https://github.com/asadnoor9/WebOSINT-Pro.git
cd WebOSINT-Pro

# 3. Virtual environment
python3 -m venv venv
source venv/bin/activate

# 4. Install (quote the extras: zsh treats [] as a glob)
pip install --upgrade pip
pip install -e '.[all]'

# 5. Make the helper scripts executable
chmod +x scripts/*.sh install.sh

# 6. Confirm the install
webosint version
webosint doctor
```

Install only what you need instead of `all`:

| Extra | Adds |
| --- | --- |
| `.[reports]` | Word, PDF and Excel export |
| `.[web]` | The local web dashboard |
| `.[integrations]` | Shodan and third-party enrichment |
| `.[database]` | Scan history persistence |
| `.[service]` | Background service and process metrics |
| `.[dev]` | Ruff, pytest, coverage, pre-commit |

Step-by-step instructions, including Windows and service installation, are in
[docs/INSTALLATION.md](docs/INSTALLATION.md).

---

## Quick start

```bash
# Add the domain you are authorized to test
echo "example.com" >> allowlist.txt

# Passive scan, HTML + JSON report
webosint scan example.com --authorized --output both

# Reports land here
ls output/reports/
```

Without `--authorized` the run is refused before a single packet leaves your
machine. That is intentional.

---

## Configuration

Configuration resolves in this order, later winning over earlier:

1. Built-in defaults
2. `config.json` in the project root
3. Environment variables
4. Command-line flags

Start from the tracked template:

```bash
cp config.example.json config.json
```

`config.json` is git-ignored, so your local values are never committed.

**API keys come from the environment only** — never from `config.json` or the
command line, so they cannot leak through shell history or the process list:

```bash
export WEBOSINT_SHODAN_KEY="..."
export WEBOSINT_NVD_KEY="..."
```

| Variable | Purpose |
| --- | --- |
| `WEBOSINT_SHODAN_KEY` | Shodan enrichment |
| `WEBOSINT_NVD_KEY` | NVD CVE lookups |
| `WEBOSINT_OUTPUT_DIR` | Relocate the whole `output/` tree |
| `WEBOSINT_RUNTIME_DIR` | PID and runtime state directory |
| `WEBOSINT_DATABASE_URL` | Scan history database |

---

## Profiles

Profiles set pacing and module selection so you do not have to tune ten flags.

| Profile | Traffic | Use it when |
| --- | --- | --- |
| `safe` | Passive only, slowest pacing | Default. Third-party or production assets |
| `medium` | Passive, balanced pacing | Routine assessment of your own estate |
| `aggressive` | Faster, more concurrent | Large scopes with a clear testing window |
| `stealth` | Minimal footprint, randomized pacing | Noise is a concern |

```bash
webosint scan example.com --authorized --profile stealth
```

Profile definitions live in `configs/profiles/`.

---

## Usage

```bash
webosint <command> [options]
```

| Command | Purpose |
| --- | --- |
| `scan` | Run a scan against an authorized target |
| `doctor` | Check the environment and report what is missing |
| `version` | Print version and build information |
| `status` | Show background service status |
| `health` | Report service health |
| `modules` | List available modules and their state |

**Frequently used options**

| Option | Effect |
| --- | --- |
| `--authorized` | Acknowledge authorization. Required |
| `--profile <name>` | `safe`, `medium`, `aggressive`, `stealth` |
| `--active` | Enable active modules. Off by default |
| `--modules <list>` | Comma-separated module selection |
| `--output <fmt>` | `json`, `html`, `markdown`, `csv`, `pdf`, `docx`, `both`, `all`, `none` |
| `--detail <level>` | `minimal`, `standard`, `detailed` |
| `--output-dir <path>` | Override the report destination |
| `-v`, `-vv` | Increase verbosity |

The complete reference is in [docs/USAGE.md](docs/USAGE.md).

---

## Examples

```bash
# Passive baseline
webosint scan example.com --authorized

# Everything passive, every report format, maximum detail
webosint scan example.com --authorized --output all --detail detailed

# Only DNS, mail and TLS posture
webosint scan example.com --authorized --modules dns,mail,ssl

# Authorized active assessment inside a testing window
webosint scan example.com --authorized --active --profile aggressive

# Minimal detail for a report you intend to share
webosint scan example.com --authorized --detail minimal --output pdf

# Quiet run for automation, JSON only
webosint scan example.com --authorized --output json --quiet
```

---

## Output

Everything generated at runtime lives under `output/`, which is git-ignored.
Nothing a scan produces is ever committed.

```
output/
├── reports/     generated reports, one set per scan
│   └── web/     reports produced by the dashboard
├── logs/        structured JSON-lines run logs
└── cache/       response and fingerprint caches
```

Relocate the whole tree — for a service account, or to keep state off the
checkout — with a single variable:

```bash
export WEBOSINT_OUTPUT_DIR=/var/lib/webosint
```

Reports are written with `0600` permissions because they contain hostnames,
addresses and evidence.

---

## Reporting

One package, `reporting/`, owns every output format. Each writer subclasses
`reporting.base.BaseReport`, so directory creation, file permissions and naming
behave identically across formats.

| Format | Flag | Requires |
| --- | --- | --- |
| JSON | `--output json` | — |
| HTML | `--output html` | — |
| Markdown | `--output markdown` | — |
| CSV | `--output csv` | — |
| PDF | `--output pdf` | `.[reports]` |
| Word | `--output docx` | `.[reports]` |

Group values: `both` (JSON + HTML), `all` (every format), `none`.

A missing optional dependency costs you that one format, never the whole report
set. Use the writers directly if you are embedding the framework:

```python
from reporting.export import write_reports

paths = write_reports(results, "output/reports", formats="all", stem="example-com")
```

---

## Modules

21 scanner modules ship in `modules/`. Passive modules run by default; active
modules require `--active`.

| Module | Mode | What it collects |
| --- | --- | --- |
| `dns` | Passive | Records, zone posture, DNSSEC |
| `whois` | Passive | Registration and ownership |
| `ip` | Passive | Addressing, ASN, ISP, geolocation |
| `ssl` | Passive | Certificates, chain, expiry, protocols |
| `http` | Passive | Headers, cookies, security policies |
| `subdomain` | Passive | Passive subdomain discovery |
| `mail` | Passive | SPF, DKIM, DMARC, MTA-STS |
| `osint` | Passive | Public exposure signals |
| `webapp` | Passive | Application fingerprinting |
| `javascript` | Passive | Script inventory, endpoint and secret hints |
| `cve` | Passive | CVE correlation for detected versions |
| `ports` | **Active** | Service and version discovery |
| `dirs` | **Active** | Content and path discovery |
| `waf` | **Active** | WAF detection and fingerprinting |
| `ids` | **Active** | IDS/IPS behaviour inference |
| `siem` | **Active** | Logging and monitoring signals |
| `database` | **Active** | Exposed database services |
| `api` | **Active** | REST and GraphQL surface |
| `websocket` | **Active** | WebSocket endpoints |
| `honeypot` | **Active** | Honeypot likelihood scoring |
| `directory` | **Active** | Categorized path evidence |

```bash
webosint modules            # list modules and their state
```

---

## Integrations

Optional, off unless configured. Absent credentials degrade gracefully.

| Integration | Adds | Needs |
| --- | --- | --- |
| Shodan | Host and service enrichment | `WEBOSINT_SHODAN_KEY` |
| NVD | CVE detail lookups | `WEBOSINT_NVD_KEY` |
| Nuclei | Template-based checks | `nuclei` on `PATH` |
| WPScan | WordPress assessment | `wpscan` on `PATH` |

---

## Web dashboard

```bash
pip install -e '.[web]'
python webserve.py                      # http://127.0.0.1:8000
```

The dashboard binds to loopback only. Exposing it on a LAN is deliberately a
two-flag decision:

```bash
python webserve.py --lan --allow-remote
```

`--host 0.0.0.0` alone falls back to loopback without `--allow-remote`, so the
server cannot be exposed by accident. Authentication is opt-in via `--auth`.
Only run it on a trusted network.

---

## Running as a service

```bash
sudo -E ./scripts/install-service.sh          # loopback only
sudo -E ./scripts/install-service.sh --lan    # reachable on the LAN

webosint status
webosint health
```

See [docs/INSTALLATION.md](docs/INSTALLATION.md) for boot behaviour, log
locations and uninstall steps.

---

## Development

```bash
pip install -e '.[all,dev]'
pre-commit install

ruff check .          # lint
ruff format .         # format
pytest -q             # 240 tests
pytest --cov          # with coverage
```

CI runs lint, the suite on Python 3.10–3.13, a packaging build, and artifact and
credential hygiene checks. All of them must pass before a merge.

---

## Project statistics

| Metric | Value |
| --- | --- |
| Language | Python 3.10 – 3.13 |
| Scanner modules | 21 |
| Report formats | 6 |
| Tests | 240 |
| Lint and format | Ruff, pinned in CI |
| Static analysis | CodeQL, weekly and per-PR |
| License | MIT |

---

## Roadmap

- [x] Passive-first engine with an enforced authorization gate
- [x] Single unified `reporting/` package with six formats
- [x] All runtime artifacts confined to `output/`
- [x] Durable distributed job queue
- [ ] Worker registry with heartbeats and lease reclamation
- [ ] Coordinator and scheduler for recurring scans
- [ ] Baselines and scan-to-scan diffing
- [ ] WebSocket live dashboard, replacing HTTP polling
- [ ] REST API with an OpenAPI schema
- [ ] Signed third-party plugins

---

## Contributing

Contributions are welcome. Start with [CONTRIBUTING.md](CONTRIBUTING.md) and the
[Code of Conduct](CODE_OF_CONDUCT.md).

Before opening a pull request: `ruff check .`, `ruff format .` and `pytest` all
pass, new behaviour has tests, and no change weakens the authorization gate,
scope enforcement or redaction.

Requests to add unauthorized-testing capability will be closed.

---

## Security

Do not open a public issue for a vulnerability. Follow the private reporting
process in [SECURITY.md](SECURITY.md).

This project is for authorized security testing. You are responsible for having
permission to test any target you point it at.

---

## License

[MIT](LICENSE) © Asad Noor

---

## Acknowledgements

Built on the work of the open-source security community, and shaped by the
engineering standards of [Nmap](https://nmap.org/),
[ProjectDiscovery](https://projectdiscovery.io/),
[OWASP](https://owasp.org/) and [Amass](https://github.com/owasp-amass/amass).

Standing on: [requests](https://requests.readthedocs.io/),
[dnspython](https://www.dnspython.org/),
[cryptography](https://cryptography.io/),
[BeautifulSoup](https://www.crummy.com/software/BeautifulSoup/),
[Flask](https://flask.palletsprojects.com/),
[ReportLab](https://www.reportlab.com/),
[python-docx](https://python-docx.readthedocs.io/) and
[Ruff](https://github.com/astral-sh/ruff).

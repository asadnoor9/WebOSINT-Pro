# WebOSINT Pro

Passive-first web OSINT and reconnaissance framework for **authorized** security testing.

[![CI](https://github.com/OWNER/REPO/actions/workflows/ci.yml/badge.svg)](https://github.com/OWNER/REPO/actions/workflows/ci.yml)

---

## Authorized use only

> **This tool is for authorized security testing and research only.**
>
> Scanning systems you do not own, or for which you do not hold **explicit written
> permission**, is illegal in most jurisdictions. You are solely responsible for how
> you use this software and for complying with all applicable laws, contracts, and
> the target's rules of engagement.
>
> The maintainers accept no liability for misuse or for any damage caused by this tool.

WebOSINT Pro refuses to run until you assert authorization:

- `--authorized` — you confirm that you hold permission to test the target.
- `--confirm-target example.com` — you re-type the exact target, or confirm it interactively.

No DNS lookup, HTTP request, or external tool runs before that gate passes.

---

## Installation

Requires Python 3.10 or newer. Full guide: [docs/INSTALLATION.md](docs/INSTALLATION.md).

```bash
git clone https://github.com/OWNER/REPO.git
cd REPO

python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

pip install --upgrade pip
pip install -e '.[all]'

chmod +x scripts/*.sh install.sh
```

Recommended system packages (optional, but DNS, WHOIS and port results are
richer with them):

```bash
sudo apt install nmap dnsutils whois        # Debian, Ubuntu, Kali, Parrot
```

Verify:

```bash
webosint doctor      # exits 0 when healthy
webosint version
```

`'.[all]'` installs every optional feature: web dashboard, PDF/Word/Excel
reporting, service management and integrations. Keep the quotes — zsh treats
bare square brackets as a glob. For a leaner install, see the
[dependency groups](docs/INSTALLATION.md#optional-dependency-groups).

Optional external tools (`subfinder`, `amass`, `whois`, `dig`, `nmap`, `nuclei`,
`wpscan`, `wafw00f`, `httpx`) are auto-detected. They are never required, are
launched only from a strict allowlist, and the intrusive ones need `--active`.

---

## Documentation

| Guide | Contents |
| --- | --- |
| [Installation](docs/INSTALLATION.md) | Requirements, dependency groups, service setup, LAN access, upgrading |
| [Usage](docs/USAGE.md) | Authorization gate, modules, profiles, reports, dashboard, configuration |
| [Troubleshooting](docs/TROUBLESHOOTING.md) | Common failures and their fixes |
| [Architecture](ARCHITECTURE.md) | Pipeline, plugin lifecycle, event bus, confidence engine |
| [Contributing](CONTRIBUTING.md) | Development workflow and standards |
| [Security policy](SECURITY.md) | Reporting vulnerabilities |
| [Changelog](CHANGELOG.md) | Release history |

---

## Quick start

```bash
# Passive OSINT (the safe default)
python webosint.py -t example.com --authorized --confirm-target example.com

# Passive, machine-readable output on stdout
python webosint.py -t example.com --authorized --confirm-target example.com --json

# Choose specific modules
python webosint.py -t example.com --authorized --confirm-target example.com -m dns,whois,ssl

# See every module and whether it is passive or active
python webosint.py --list-modules
```

---

## Passive vs active mode

| | Passive (default) | Active (`--active`) |
|---|---|---|
| Traffic to target | None or ordinary web requests | Intrusive probes |
| Techniques | DNS, WHOIS, certificate transparency, public archives, passive sources | Port scans, directory brute force, WAF probing, vulnerability templates |
| Third-party tools | `subfinder`, `amass -passive`, `whois`, `dig` | `nmap`, `nuclei`, `wpscan`, `wafw00f`, `httpx` |
| Detection risk | Low | High — will appear in the target's logs |
| Requires | `--authorized` | `--authorized` **and** `--active` |

Active modules are silently skipped in passive mode and reported in the summary,
so a passive run can never accidentally send an intrusive probe.

```bash
# Active mode: only with written authorization that covers intrusive testing
python webosint.py -t example.com --authorized --confirm-target example.com --active
```

---

## Safety controls

| Control | Default | Flag |
|---|---|---|
| Authorization required | enforced | `--authorized` |
| Target confirmation | enforced | `--confirm-target <target>` |
| Passive only | on | `--active` to opt out |
| TLS certificate verification | **on** | `--insecure-tls-i-accept-the-risk` |
| Localhost / private / reserved / link-local IPs | blocked | `--allow-private` |
| Cloud metadata endpoints (169.254.169.254) | always blocked | — |
| Redirect following | max 3 hops, each re-validated | `--max-redirects` |
| Non-HTTP(S) schemes | blocked | — |
| Target allowlist | optional | `--allowlist configs/allowlist.json` |
| Shell execution | never used | — |
| Telemetry / analytics | none, ever | — |

Disabling TLS verification marks **every** finding in the run as `UNTRUSTED` in the
console output and in the reports.

### Allowlist

```json
{
  "targets": ["example.com", "test.example.org", "93.184.216.0/24"]
}
```

Subdomains of a listed domain and addresses inside a listed CIDR are permitted;
everything else is refused.

---

## Privacy behaviour

- **Data minimization** — `--detail minimal|standard|detailed` (default `standard`).
  `minimal` drops emails, personal names and other PII entirely.
- **Redaction everywhere** — API keys, tokens, JWTs, cookies, credentials, internal
  IPs and local filesystem paths are scrubbed from the console, logs, reports and
  exception messages.
- **No raw capture** — raw HTTP bodies, request headers and query data are never
  written unless you pass `--keep-raw`.
- **No stack traces** — errors are reported as short redacted messages.
- **Secrets come from the environment only** — never from the CLI or config file, so
  they cannot leak into your shell history. See `.env.example`.
- **Retention** — reports older than `--retention-days` (30) and logs older than
  `--log-retention-days` (14) are cleaned up automatically; temporary files are
  created `0600` and removed at the end of each run. Disable with `--no-cleanup`.
- **Telemetry** — none. There is no analytics or outbound reporting of any kind.

---

## Output

Default console output is deliberately quiet: actionable findings, a summary,
warnings and errors only.

```
  Target  example.com
  Mode    passive  detail=standard tls=verified
  Modules 12

  Actionable findings
   MEDIUM   Missing Content-Security-Policy  [likely, confidence 85%, via http]
   LOW      Certificate expires in 19 days   [confirmed, confidence 99%, via ssl]

  Scan complete | 24.6s | modules 12/12 | findings 47 | medium=1  low=1
```

| Verbosity | Shows |
|---|---|
| `-q` / `--quiet` | errors only |
| default | warnings, errors, summary |
| `-v` | per-module progress and findings |
| `-vv` | per-request debug detail |

Findings are deduplicated across modules using stable normalized identifiers, ordered
deterministically by severity then identifier, and annotated with a confidence score,
source attribution, evidence summary and status label (`confirmed`, `likely`,
`possible`, `unverified`, `untrusted`).

### Report file formats

Reports are written to `reports/` with `0600` permissions. Choose one with
`--output`, or use `--output all` to write every format at once.

| `--output` | File | Best for |
|---|---|---|
| `json` (default) | `.json` | Automation, diffing, piping into other tools |
| `html` | `.html` | A styled, self-contained web page you can open in a browser |
| `markdown` | `.md` | Pasting into tickets, wikis or Git |
| `csv` | `.csv` | Spreadsheets — one row per finding, opens cleanly in Excel |
| `docx` | `.docx` | Word deliverables and client reports |
| `pdf` | `.pdf` | Fixed-layout reports for sign-off or archiving |
| `all` | all of the above | |
| `none` | — | Console only, nothing written to disk |

Word and PDF export need two extra libraries:

```bash
pip install -r requirements-web.txt     # or: pip install '.[reports]'
```

Examples:

```bash
# A PDF for the client and a CSV for triage
python webosint.py -t example.com --authorized --confirm-target example.com --output all

# Word document only
python webosint.py -t example.com --authorized --confirm-target example.com --output docx
```

`--json` prints the full machine-readable result to stdout, separately from the
files written to disk.

---

## Web interface

A local browser UI drives the same pipeline as the CLI, including the mandatory
authorization gate.

```bash
pip install -r requirements-web.txt
python webserve.py                 # http://127.0.0.1:8000
```

From the browser you can set the target, tick the authorization acknowledgement,
re-type the target to confirm, pick passive or active mode, choose a profile and
detail level, select individual modules, tune threads/timeout/rate limit, and
tick which file formats to generate.

The same safety rules apply — the UI cannot bypass them:

- the authorization checkbox and a matching target confirmation are both required
- localhost, private and reserved ranges stay blocked unless you opt in
- active modules stay off until you explicitly enable them
- TLS verification stays on by default
- findings are redacted according to the selected detail level
- errors are shown as short messages, never stack traces

### Background scans and progress

Every scan runs in a background worker, so you can close the tab, start another
scan, or come back later. The job page shows a live progress bar, the modules
currently running, elapsed time, and a **Cancel scan** button. `/jobs` lists every
scan from the current server session with its status, target, mode and findings
count.

### Scan speed

A speed selector sets threads, rate limit, timeout and inter-request delay in one
choice:

| Speed | Concurrency | Character |
| --- | --- | --- |
| Slow | 2 | Gentle and quiet; best for fragile or monitored hosts |
| Normal | 5 | Balanced default |
| Fast | 12 | Noticeably louder |
| Turbo | 24 | Loud; expect rate limiting and IDS attention |

The individual threads/timeout/rate-limit fields still win if you fill them in,
and the selected profile keeps its own ceiling — a `safe` profile will not let
Turbo run at full speed.

### Verbosity

A verbosity selector controls the live log panel on the job page: **Quiet**
(errors only), **Normal**, **Verbose** (per-request debug) and **Debug** (trace).
Log lines are streamed incrementally and pass through the same redaction filter
as the log files, so secrets never reach the browser.

### Reports in the portal

When a scan finishes, every generated file is listed with both **Open** and
**Download**. HTML, Markdown, JSON and CSV reports open directly in the portal;
DOCX and PDF download. Opened reports are served with a sandboxing
`Content-Security-Policy` so a report can never script against the portal.

### Host and infrastructure

The job page also summarises what was observed about the host:

- **Network** — resolved IPs, ISP, organisation, ASN, geo, hosting/proxy flags
- **Web server** — product and version (for example Apache 2.4.65, nginx, IIS),
  banner, `X-Powered-By`, CDN and detected technologies
- **Operating system** — best guess, device type and the source of the guess
- **Exposed services** — port, protocol, state, service, product and version

This is derived from data the scan already collected; it does not send extra
requests.

### Access from other machines on your network

By default the server binds to `127.0.0.1` and is unreachable from anywhere else.
To reach it from another machine on the same VLAN:

```bash
python webserve.py --lan
```

`--lan` binds all interfaces and prints both the local and network URLs. **No
access token is required by default** — anyone who can reach the port can open
the UI, so only do this on a trusted, isolated network. The launcher prints a
warning to remind you.

Token authentication is available when you want it:

```bash
python webserve.py --lan --auth                               # generate a token and require it
python webserve.py --lan --auth-token "$WEBOSINT_WEB_TOKEN"   # pick your own token
python webserve.py --lan --no-auth                            # force the token off (default)
python webserve.py --lan --self-signed                        # HTTPS with a throwaway cert
python webserve.py --lan --tls-cert cert.pem --tls-key key.pem
python webserve.py --port 8080
```

With `--auth`, the token is printed as a ready-to-click URL; other machines supply
it once (`?token=...`, or an `Authorization: Bearer` header), after which it is
kept in an HttpOnly, SameSite=Strict cookie.

The authorization gate, private-range blocking and passive-by-default rules are
unaffected by this setting — disabling the token only removes the portal login,
not any scan safety control.

If the page is unreachable from another host, check the server firewall
(`sudo ufw allow 8000/tcp` on Debian/Kali) — the listener itself is already
bound to every interface with `--lan`.

---

### Running in the background

The web interface can detach from your terminal and keep serving:

```bash
# Start detached (survives closing the terminal)
python webserve.py --lan --background

# Check on it
python webserve.py --status

# Stop it
python webserve.py --stop
```

In background mode all output is appended to a log file instead of the console.
By default the PID and log live in `~/.webosint/`:

| File | Purpose |
| --- | --- |
| `~/.webosint/webosint-web.pid` | PID of the detached server |
| `~/.webosint/webosint-web.log` | Server and scan output |

Override them with `--pid-file` / `--log-file`, or move the whole directory with
the `WEBOSINT_RUNTIME_DIR` environment variable. Starting a second background
server while one is already running is refused rather than silently duplicated.

### Starting on boot

To have the interface come up automatically after a reboot, install it as a
systemd service. Any flags you pass to the installer are forwarded to
`webserve.py`:

```bash
# Localhost only
sudo ./scripts/install-service.sh

# Reachable from other machines on your network, protected by a token
sudo ./scripts/install-service.sh --lan --auth
```

The installer runs the service as your own user (not root), prefers the project
virtualenv if one exists, and enables the unit so it starts at boot.

```bash
systemctl status webosint-web        # is it up?
journalctl -u webosint-web -f        # follow the logs
sudo systemctl restart webosint-web  # restart
sudo ./scripts/install-service.sh --uninstall
```

Do not combine the service with `--background`: systemd supervises the process
itself, so the server must stay in the foreground under its control.

> Exposing the UI on a network lets anyone who can reach the port start scans.
> Pair `--lan` with `--auth` and keep it on trusted networks.

## Configuration

Environment variables use the `WEBOSINT_` prefix. Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

API keys are read **only** from the environment:

| Variable | Purpose |
|---|---|
| `WEBOSINT_SHODAN_KEY` | Shodan enrichment (optional) |
| `WEBOSINT_NVD_KEY` | NVD CVE lookups (optional) |

---

## Engine 3.0 architecture

The 3.0 engine adds a layered platform core in `engine/` alongside the existing
`core/` and `modules/` packages. Legacy modules are **adapted**, not rewritten,
so every existing scan keeps working exactly as before while gaining evidence
backed scoring, dynamic plugin selection and multi-audience reporting.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full reference.

### Why scans got faster and quieter

- **Technology-aware selection.** The plan is derived from what was actually
  fingerprinted. A statically hosted Next.js site no longer runs WordPress, PHP,
  database, SIEM, IDS or honeypot checks. Every skip is recorded with a reason
  and shown in the technical report.
- **Shared cache with single-flight coalescing.** DNS, HTTP and TLS lookups are
  performed once and reused. Ten plugins asking for the same record produce one
  request.
- **Per-plugin deadlines.** A stalled plugin is abandoned instead of holding the
  whole scan open.

### Why findings became more trustworthy

Confidence is computed from evidence rather than assigned:

| Rule | Effect |
|---|---|
| Evidence kinds are weighted | DNS/TLS/certificate are authoritative; an HTML body match is weak |
| Evidence combines with noisy-OR | Two independent indicators beat one strong one |
| Repeated same-kind evidence decays | Five HTML matches are still "the HTML said so" |
| A single evidence kind is capped at 72% | **One indicator can never produce a reported finding** |
| Below 80% confidence is suppressed | Kept for analyst review, excluded from reports |
| 90%+ with multi-indicator validation | Marked `verified` |

Every finding carries `confidence`, `severity`, `verified`, `evidence`,
`validation_method`, `risk_score`, `exploitability` and
`false_positive_probability`, plus CWE / OWASP / MITRE ATT&CK / PCI DSS / NIST
mappings where they apply.

---

## Service management

Install the console command with `pip install -e .`, then:

```bash
webosint start          # start in the background (single instance)
webosint stop           # graceful shutdown
webosint restart
webosint reload         # reload config and plugins without dropping the process
webosint status         # state, PID, uptime, memory, CPU, threads, queue, plugins
webosint health         # health checks; exit 0 healthy, 1 degraded, 2 unhealthy
webosint logs -f        # tail the service log
webosint version
webosint update         # git pull + reinstall (refuses on a dirty tree)
webosint doctor         # diagnose the installation and print exact fixes
```

Add `--json` to any command for machine-readable output.

**`webosint doctor` is the fastest way to resolve missing-dependency errors** -
it reports exactly which optional packages are absent and the command to install
each one.

### Network access

By default the dashboard binds to `127.0.0.1` and is unreachable from other
machines. Two flags are needed to change that: `--lan` selects the bind address
and `--allow-remote` confirms you meant it. The installer adds the second one
for you:

```bash
sudo ./scripts/install-service.sh --lan
```

Then allow the port for your subnet only:

```bash
sudo ufw allow from 192.168.1.0/24 to any port 8000 proto tcp
```

Verify the bind address is `0.0.0.0` and not `127.0.0.1`:

```bash
ss -ltnp | grep 8000
```

> **The dashboard has no authentication.** Anyone who can reach the port can
> launch scans from your machine against any target and read every stored
> report. Scope the firewall rule to trusted hosts, never port-forward it to
> the internet, and prefer `--lan --auth --self-signed` on a shared network.


### Starting on boot

| Platform | Install | Manage |
|---|---|---|
| Linux | `sudo ./scripts/install-service.sh` | `systemctl start|stop|restart|status webosint` |
| macOS | `sudo launchctl load -w /Library/LaunchDaemons/pk.webosint.plist` | `launchctl start|stop pk.webosint` |
| Windows | `.\scripts\install-service.ps1` | `sc.exe start WebOSINT`, `Get-Service WebOSINT`, `services.msc` |

All three start at boot and restart automatically after a crash with a backoff.

---

## Scan history and inventory

Scans, findings, technologies, assets, certificates, DNS records, reports and
risk scores are persisted. SQLite is the default and needs no setup; point
`WEBOSINT_DATABASE_URL` at a PostgreSQL or MySQL DSN to use a server instead:

```bash
export WEBOSINT_DATABASE_URL="postgresql+psycopg://user:pass@localhost/webosint"
```

---

## Optional dependencies

Several capabilities are optional so the base install stays small. Missing ones
degrade gracefully and are reported by `webosint doctor`.

```bash
pip install '.[reports]'   # Word, PDF and Excel reports
pip install '.[service]'   # memory and CPU metrics in `webosint status`
pip install '.[web]'       # web dashboard
pip install '.[all]'       # everything above
```

---

## Development

```bash
ruff check .          # lint
ruff format .         # format
pytest                # tests (no network access required)
```

The test suite covers authorization, target blocking, TLS defaults, redaction,
deduplication and output behaviour. No test performs external reconnaissance.

---

## Contributing & security

- [CONTRIBUTING.md](CONTRIBUTING.md) — development workflow and coding standards.
- [SECURITY.md](SECURITY.md) — how to report a vulnerability.

---

## License

Released under the [MIT License](LICENSE).

The license grants permission to use the software. It does **not** grant
permission to scan anything. Authorization for every target is your
responsibility, and the software is provided without warranty of any kind.

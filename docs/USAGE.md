# Usage guide

- [The authorization gate](#the-authorization-gate)
- [Passive and active modes](#passive-and-active-modes)
- [Command-line scanning](#command-line-scanning)
- [Choosing modules](#choosing-modules)
- [Scan profiles](#scan-profiles)
- [Output and reports](#output-and-reports)
- [Privacy and detail levels](#privacy-and-detail-levels)
- [The web dashboard](#the-web-dashboard)
- [Service commands](#service-commands)
- [Configuration](#configuration)
- [Interpreting results](#interpreting-results)

---

## The authorization gate

Every scan requires you to assert authorization **and** name the target twice.
The second flag is a deliberate speed bump against typos and copy-paste errors:

```bash
python webosint.py -t example.com --authorized --confirm-target example.com
```

If the two targets disagree, or `--authorized` is missing, nothing runs and no
network request is made. Private and reserved address ranges are refused unless
you explicitly pass `--allow-private`, which is intended for lab use.

You can constrain scanning further with an allowlist file:

```bash
python webosint.py -t app.example.com --authorized --confirm-target app.example.com \
  --allowlist ./scope.txt
```

One entry per line; domains and CIDR ranges are both accepted. Anything outside
the list is refused, including hosts reached through redirects.

---

## Passive and active modes

**Passive is the default.** It uses public data sources and ordinary web
requests to the target. It does not probe ports, brute-force paths or run
vulnerability templates.

**Active mode** (`--active`) unlocks the intrusive modules: port scanning,
directory discovery, WAF and IDS probing, database and API testing, websocket
checks and honeypot detection. Use it only when your authorization explicitly
covers intrusive testing.

```bash
python webosint.py -t example.com --authorized --confirm-target example.com --active
```

See which modules are which:

```bash
python webosint.py --list-modules
```

---

## Command-line scanning

```bash
# Passive scan, human-readable output
python webosint.py -t example.com --authorized --confirm-target example.com

# Machine-readable output on stdout
python webosint.py -t example.com --authorized --confirm-target example.com --json

# Specific modules only
python webosint.py -t example.com --authorized --confirm-target example.com -m dns,whois,ssl

# Everything except the slow ones
python webosint.py -t example.com --authorized --confirm-target example.com --skip-modules ports,dirs

# Quieter or louder
python webosint.py -t example.com --authorized --confirm-target example.com -q
python webosint.py -t example.com --authorized --confirm-target example.com -vv
```

Useful pacing flags: `--threads`, `--timeout`, `--delay`, `--retries` and
`--rate-limit`. Lower concurrency and a positive `--delay` make a scan slower
but much less conspicuous.

---

## Choosing modules

```bash
python webosint.py --list-modules
```

Modules are grouped by family: DNS and mail, WHOIS and registration, IP and
network, HTTP and headers, TLS, technology fingerprinting, content and
metadata, plus the active-only families.

You rarely need to pick manually. The engine fingerprints the target first and
automatically skips families that cannot apply — WordPress and PHP probes are
not run against a statically exported Next.js site, for example. This is the
largest single reason scans finish faster than they used to. Override the
selection with `-m` or `--skip-modules` when you need to.

---

## Scan profiles

```bash
python webosint.py -t example.com --authorized --confirm-target example.com --profile stealth
```

| Profile | Intent |
| --- | --- |
| `safe` | Minimal footprint, passive only |
| `medium` | Balanced default |
| `aggressive` | Maximum coverage; slowest and loudest |
| `stealth` | Low concurrency, delays, reduced request volume |
| `bugbounty` | Tuned for scope-limited bug bounty work |
| `api-only` | API surface discovery and testing |

---

## Output and reports

```bash
# Single format
python webosint.py -t example.com --authorized --confirm-target example.com --output html

# Everything
python webosint.py -t example.com --authorized --confirm-target example.com --output all

# Somewhere specific, with a chosen name
python webosint.py -t example.com --authorized --confirm-target example.com \
  --output pdf --output-dir ./client-reports --report-name acme-external
```

Available: `json`, `html`, `markdown`, `csv`, `docx`, `pdf`, `both`, `all`,
`none`. PDF, Word and Excel need the `reports` extra.

JSON output is deterministic — the same findings serialise identically every
time — so you can diff two scans meaningfully or commit them to a repository.

---

## Privacy and detail levels

```bash
python webosint.py -t example.com --authorized --confirm-target example.com --detail minimal
```

| Level | Contains |
| --- | --- |
| `minimal` | Findings and severities; identifiers heavily redacted |
| `standard` | Default. Findings with supporting evidence, sensitive values redacted |
| `detailed` | Full evidence, for internal use |

Redaction applies to every output path, including logs and error messages. Raw
HTTP exchanges are never persisted unless you pass `--keep-raw`. Retention is
enforced automatically:

```bash
--retention-days 30        # delete reports older than this
--log-retention-days 14
--no-cleanup               # disable automatic cleanup
```

Telemetry is off. `--telemetry` opts in; nothing is collected otherwise.

---

## The web dashboard

```bash
python webserve.py
```

Open `http://127.0.0.1:8000`. From there you can:

- start a scan and pick modules, profile, detail level and output formats
- run scans **in the background** and close the browser
- watch **live progress** per stage with a running elapsed time
- adjust **scan speed** between slow/stealthy and fast presets
- set **verbosity** from quiet to debug and follow the live log
- cancel a running scan
- browse past jobs, and **view or download** any generated report in the portal
- read the host and infrastructure summary: operating system, network, ISP,
  exposed port versions and services, and the web hosting stack

---

## Service commands

```bash
webosint start          # start the background service
webosint stop
webosint restart
webosint status         # process and systemd state
webosint health         # health check with metrics
webosint logs           # recent log output
webosint doctor         # environment diagnosis
webosint version
```

---

## Configuration

Copy `config.example.json` to `config.json` before editing; `config.json`
is git-ignored so local values are never committed.

Precedence: command-line flags, then environment variables, then `config.json`,
then defaults.

Copy `.env.example` to `.env` and fill in what you need:

| Variable | Purpose |
| --- | --- |
| `WEBOSINT_SHODAN_KEY` | Shodan enrichment |
| `WEBOSINT_NVD_KEY` | Higher NVD rate limits |
| `WEBOSINT_WEB_TOKEN` | Dashboard auth token |
| `WEBOSINT_RUNTIME_DIR` | Runtime state location (default `~/.webosint`) |
| `WEBOSINT_DATABASE_URL` | History database (default SQLite) |
| `WEBOSINT_QUEUE_PATH` | Job queue database |

`.env` is git-ignored. Never commit real keys.

---

## Interpreting results

Findings carry a **confidence score** and the evidence behind them. Anything
below the reporting threshold is withheld rather than guessed at, so an absent
finding means "not established", not "proven absent".

Correlation suppresses known false positives: email authentication is evaluated
against the organisational domain rather than the subdomain you scanned, and
origin-server observations are interpreted correctly when a CDN sits in front.

Severities are `critical`, `high`, `medium`, `low` and `info`. The risk summary
aggregates them into an overall posture score.

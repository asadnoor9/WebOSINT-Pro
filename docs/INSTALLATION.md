# Installation guide

Everything below assumes you have written authorization to assess whatever you
point this tool at. WebOSINT Pro refuses to run without it.

- [Requirements](#requirements)
- [Standard installation](#standard-installation)
- [System packages](#system-packages)
- [Optional dependency groups](#optional-dependency-groups)
- [Verifying the installation](#verifying-the-installation)
- [Running the web dashboard](#running-the-web-dashboard)
- [Installing as a service](#installing-as-a-service)
- [Network access from other machines](#network-access-from-other-machines)
- [Upgrading](#upgrading)
- [Uninstalling](#uninstalling)

---

## Requirements

| Requirement | Notes |
| --- | --- |
| Python 3.10 or newer | 3.11 or 3.12 recommended |
| Linux, macOS or Windows | Service installation is supported on Linux (systemd), macOS (LaunchDaemon) and Windows (Service) |
| ~200 MB disk | Plus whatever your stored reports need |
| Outbound network access | Only to the targets you are authorized to assess, and to public data sources |

No external tool is mandatory. `nmap`, `dig`, `whois`, `subfinder`, `amass`,
`nuclei`, `wpscan`, `wafw00f` and `httpx` are auto-detected when present and
silently skipped when absent. Intrusive ones additionally require `--active`.

---

## Standard installation

```bash
git clone https://github.com/OWNER/REPO.git
cd REPO

python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

pip install --upgrade pip
pip install -e '.[all]'

chmod +x scripts/*.sh install.sh
```

`pip install -e '.[all]'` installs the project in editable mode with every
optional feature: the web dashboard, PDF/Word/Excel reporting, service
management and the third-party integrations. It also installs the `webosint`
command into your virtual environment.

If you want a lean install instead, see
[optional dependency groups](#optional-dependency-groups).

> **Quoting note.** The single quotes around `'.[all]'` matter. Without them,
> zsh interprets the square brackets as a glob and the install fails.

---

## System packages

These are optional but recommended — DNS, WHOIS and port data are noticeably
richer when they are present.

**Debian, Ubuntu, Kali, Parrot:**

```bash
sudo apt install nmap dnsutils whois
```

**Fedora, RHEL:**

```bash
sudo dnf install nmap bind-utils whois
```

**Arch:**

```bash
sudo pacman -S nmap bind whois
```

**macOS:**

```bash
brew install nmap bind whois
```

`install.sh` can install these plus the optional Go and Ruby recon tools for
you, but it is not required and is not part of the standard install path.
If you do run it, run it **before** `pip install -e '.[all]'`.

---

## Optional dependency groups

`pip install -e '.[all]'` is the recommended install. If you prefer to keep the
footprint small, install only what you need:

```bash
pip install -e .                    # core scanning and JSON/Markdown/HTML reports
pip install -e '.[web]'             # + the web dashboard (Flask)
pip install -e '.[reports]'         # + PDF, Word and Excel export
pip install -e '.[service]'         # + background service and health metrics
pip install -e '.[integrations]'    # + third-party data sources
pip install -e '.[validation]'      # + strict config validation
pip install -e '.[dev]'             # + pytest, ruff, pre-commit
```

| Group | Provides | Without it |
| --- | --- | --- |
| `web` | Flask dashboard, background scans, in-portal reports | CLI only |
| `reports` | `--output pdf`, `docx`, `xlsx` | Those formats raise a clear error |
| `service` | `webosint status/health`, process metrics | Service commands degrade |
| `integrations` | Shodan and related enrichment | Those sources are skipped |
| `validation` | Schema-checked configuration | Basic validation only |
| `dev` | Test and lint tooling | Cannot run the suite |

Groups combine: `pip install -e '.[web,reports]'`.

---

## Verifying the installation

```bash
webosint doctor      # environment check; exits 0 when healthy
webosint version
pytest tests -q      # requires the dev group
```

`webosint doctor` reports two severities. **Blocking** problems (unsupported
Python, unwritable runtime directory) make it exit non-zero. **Warnings**
(start-on-boot not enabled, an optional tool missing) do not.

If `webosint` prints a `usage: webosint [-h] [-t TARGET] ...` help screen with
no subcommands, an old wrapper is shadowing the packaged command. See
[TROUBLESHOOTING.md](TROUBLESHOOTING.md#the-webosint-command-runs-the-wrong-program).

---

## Running the web dashboard

```bash
source venv/bin/activate
python webserve.py                       # http://127.0.0.1:8000
python webserve.py --port 9000
python webserve.py --background          # detached; survives closing the terminal
python webserve.py --status
python webserve.py --stop
```

The dashboard runs **without authentication by default**, which is why it binds
to localhost only. Enable a token with `--auth`, which prints a generated token
at startup, or supply your own with `--auth-token`.

---

## Installing as a service

Runs the dashboard in the background and starts it on boot.

```bash
source venv/bin/activate
sudo -E ./scripts/install-service.sh              # localhost only
sudo -E ./scripts/install-service.sh --lan        # reachable on your network
sudo -E ./scripts/install-service.sh --lan --auth # network + token auth
```

`sudo -E` matters: it preserves `VIRTUAL_ENV` so the installer picks your
virtual environment's interpreter rather than the system Python.

Managing it:

```bash
systemctl status webosint
sudo systemctl restart webosint
journalctl -u webosint -f
sudo ./scripts/install-service.sh --uninstall
```

Runtime state (PID file, logs, database, stored reports) lives in
`~/.webosint`, outside the repository, so it survives upgrades.

Windows and macOS equivalents are `scripts/install-service.ps1` and the
LaunchDaemon plist in `scripts/`.

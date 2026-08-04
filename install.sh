#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
#  WebOSINT Pro — Installer
#  Usage:
#    ./install.sh              normal install (coloured progress)
#    ./install.sh -v           verbose: show command output
#    ./install.sh -vv          very verbose: full output + set -x
#    ./install.sh --dry-run    print steps only, install nothing
#    ./install.sh --no-go      skip Go-based tools
#    ./install.sh --no-python  skip Python tools (just system deps)
# ═══════════════════════════════════════════════════════════════════
set -euo pipefail

# ── CLI flags ────────────────────────────────────────────────────────
VERBOSE=0
DRY_RUN=0
SKIP_GO=0
SKIP_PYTHON_TOOLS=0

for arg in "$@"; do
  case "$arg" in
    -vv|--vv)  VERBOSE=2 ;;
    -v|--v)    VERBOSE=1 ;;
    --dry-run) DRY_RUN=1 ;;
    --no-go)   SKIP_GO=1 ;;
    --no-python) SKIP_PYTHON_TOOLS=1 ;;
    -h|--help)
      echo "Usage: ./install.sh [-v|-vv] [--dry-run] [--no-go] [--no-python]"
      exit 0 ;;
  esac
done

[[ $VERBOSE -ge 2 ]] && set -x

# ── Colours ──────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
  R='\033[0;31m'  G='\033[0;32m'  Y='\033[1;33m'
  C='\033[0;36m'  B='\033[0;34m'  M='\033[0;35m'
  BOLD='\033[1m'  DIM='\033[2m'   RESET='\033[0m'
else
  R='' G='' Y='' C='' B='' M='' BOLD='' DIM='' RESET=''
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Progress state ───────────────────────────────────────────────────
TOTAL_STEPS=9
CURRENT_STEP=0
ERRORS=()
SKIPPED=()
INSTALLED=()

# ── Output helpers ────────────────────────────────────────────────────
_header() {
  CURRENT_STEP=$(( CURRENT_STEP + 1 ))
  local pct=$(( CURRENT_STEP * 100 / TOTAL_STEPS ))
  local filled=$(( pct / 5 ))
  local bar
  bar="$(printf '%0.s█' $(seq 1 $filled))$(printf '%0.s░' $(seq 1 $((20-filled))))"
  echo -e "\n${BOLD}${C}[${CURRENT_STEP}/${TOTAL_STEPS}] [$bar] ${pct}%${RESET}"
  echo -e "${BOLD}${B}━━━ $* ━━━${RESET}"
}

_ok()      { echo -e "  ${G}✔${RESET}  $*"; }
_skip()    { echo -e "  ${Y}↷${RESET}  ${DIM}$* (skipped)${RESET}"; SKIPPED+=("$*"); }
_fail()    { echo -e "  ${R}✘${RESET}  $*"; ERRORS+=("$*"); }
_info()    { echo -e "  ${C}›${RESET}  $*"; }
_debug()   { [[ $VERBOSE -ge 1 ]] && echo -e "  ${DIM}· $*${RESET}"; }
_cmd_out() { [[ $VERBOSE -ge 1 ]] && echo -e "${DIM}$*${RESET}"; }

# Run a command, suppress output unless -v
_run() {
  local desc="$1"; shift
  _debug "running: $*"
  if [[ $DRY_RUN -eq 1 ]]; then
    _info "[dry-run] $*"
    return 0
  fi
  if [[ $VERBOSE -ge 1 ]]; then
    "$@" 2>&1 | sed 's/^/    /'
    local rc=${PIPESTATUS[0]}
  else
    "$@" &>/tmp/webosint_install.log
    local rc=$?
  fi
  if [[ $rc -ne 0 ]]; then
    _fail "$desc failed (exit $rc)"
    [[ $VERBOSE -eq 0 ]] && cat /tmp/webosint_install.log | sed 's/^/    /' || true
    return 1
  fi
  INSTALLED+=("$desc")
  return 0
}

# Check if a binary exists, print found/not-found
_check_bin() {
  local bin="$1"
  if command -v "$bin" &>/dev/null; then
    _ok "$bin  →  $(command -v "$bin")"
    return 0
  else
    return 1
  fi
}

# ── Banner ────────────────────────────────────────────────────────────
echo -e "${C}"
cat << 'BANNER'
 __        __   _      ___  ____  ___ _   _ _____   ____
 \ \      / /__| |__  / _ \/ ___|_ _| \ | |_   _| |  _ \ _ __ ___
  \ \ /\ / / _ \ '_ \| | | \___ \| ||  \| | | |   | |_) | '__/ _ \
   \ V  V /  __/ |_) | |_| |___) | || |\  | | |   |  __/| | | (_) |
    \_/\_/ \___|_.__/ \___/|____/___|_| \_| |_|   |_|   |_|  \___/
BANNER
echo -e "${RESET}"
echo -e "${BOLD}  WebOSINT Pro  ─  Installer${RESET}"
[[ $DRY_RUN -eq 1 ]] && echo -e "  ${Y}⚠  DRY-RUN mode — nothing will be installed${RESET}"
[[ $VERBOSE -ge 1 ]] && echo -e "  ${DIM}verbose=${VERBOSE}${RESET}"
echo ""

# ── Step 1: Detect OS ─────────────────────────────────────────────────
_header "Detecting OS & Package Manager"
PKG_MGR="unknown"
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
  if   command -v apt-get &>/dev/null; then PKG_MGR="apt"
  elif command -v pacman  &>/dev/null; then PKG_MGR="pacman"
  elif command -v dnf     &>/dev/null; then PKG_MGR="dnf"
  elif command -v yum     &>/dev/null; then PKG_MGR="yum"
  fi
elif [[ "$OSTYPE" == "darwin"* ]]; then PKG_MGR="brew"
fi

if [[ "$PKG_MGR" == "unknown" ]]; then
  _fail "Could not detect package manager. Install manually."
  exit 1
fi
_ok "OS: $OSTYPE  |  package manager: ${BOLD}$PKG_MGR${RESET}"

# Kali / ParrotOS detection
if [[ -f /etc/os-release ]]; then
  source /etc/os-release 2>/dev/null || true
  _info "Distribution: ${PRETTY_NAME:-unknown}"
fi

# ── Step 2: System dependencies ───────────────────────────────────────
_header "System Dependencies (nmap, python3, git, curl, dnsutils)"

_install_sys() {
  case $PKG_MGR in
    apt)
      _run "apt update"     sudo apt-get update -qq
      _run "system-deps"    sudo apt-get install -y \
        python3 python3-pip python3-venv python3-dev \
        nmap dnsutils whois git curl wget \
        build-essential libssl-dev libffi-dev golang-go ruby-full
      ;;
    pacman)
      _run "system-deps"  sudo pacman -Sy --noconfirm \
        python python-pip nmap bind-tools whois \
        git curl wget base-devel go ruby
      ;;
    dnf|yum)
      _run "system-deps"  sudo $PKG_MGR install -y \
        python3 python3-pip python3-devel nmap \
        bind-utils whois git curl wget \
        gcc openssl-devel golang ruby
      ;;
    brew)
      _run "brew-deps"    brew install python3 nmap git curl wget go ruby
      ;;
  esac
}

_install_sys

# Report what's available
for bin in python3 pip3 nmap git curl wget go ruby; do
  if command -v "$bin" &>/dev/null; then
    ver=$("$bin" --version 2>&1 | head -1 || echo "?")
    _ok "$bin  ─  ${DIM}$ver${RESET}"
  else
    _fail "$bin not found after install attempt"
  fi
done

# ── Step 3: Python virtualenv ─────────────────────────────────────────
_header "Python Virtual Environment"

VENV="$SCRIPT_DIR/venv"
if [[ ! -d "$VENV" ]]; then
  _run "create-venv"  python3 -m venv "$VENV"
  _ok "Created: $VENV"
else
  _info "venv already exists: $VENV"
fi

# shellcheck disable=SC1090
source "$VENV/bin/activate"
_run "upgrade-pip"  pip install --upgrade pip -q
_ok "pip: $(pip --version)"

# ── Step 4: Python packages ───────────────────────────────────────────
_header "Python Packages (requirements.txt)"

REQS="$SCRIPT_DIR/requirements.txt"
if [[ -f "$REQS" ]]; then
  _info "Installing from requirements.txt …"
  if [[ $VERBOSE -ge 1 ]]; then
    pip install -r "$REQS" 2>&1 | grep -E "^(Collecting|Installing|Successfully|ERROR)" | sed 's/^/    /'
  else
    _run "pip-install"  pip install -r "$REQS" -q
  fi
  _ok "requirements.txt installed"
else
  _fail "requirements.txt not found at $REQS"
fi

# ── Step 5: Python security tools (wafw00f, theHarvester) ─────────────
_header "Python Security Tools"

if [[ $SKIP_PYTHON_TOOLS -eq 0 ]]; then

  # wafw00f
  if ! command -v wafw00f &>/dev/null; then
    _info "Installing wafw00f …"
    _run "wafw00f"  pip install wafw00f -q && _ok "wafw00f installed" || _fail "wafw00f install failed"
  else
    _ok "wafw00f already present  →  $(command -v wafw00f)"
  fi

  # theHarvester
  if ! command -v theHarvester &>/dev/null; then
    _info "Installing theHarvester …"
    TH_DIR="/tmp/theHarvester_install"
    rm -rf "$TH_DIR"
    if _run "clone-theHarvester"  git clone --depth 1 https://github.com/laramies/theHarvester "$TH_DIR" -q; then
      _run "theHarvester-deps"  pip install -r "$TH_DIR/requirements/base.txt" -q
      install -m 755 "$TH_DIR/theHarvester.py" "$VENV/bin/theHarvester" 2>/dev/null \
        || cp "$TH_DIR/theHarvester.py" "$VENV/bin/theHarvester"
      chmod +x "$VENV/bin/theHarvester"
      _ok "theHarvester installed"
    else
      _fail "theHarvester clone failed (check internet)"
    fi
  else
    _ok "theHarvester already present  →  $(command -v theHarvester)"
  fi

else
  _skip "Python security tools (--no-python)"
fi

# ── Step 6: Go tools (subfinder, amass, nuclei) ───────────────────────
_header "Go-based Tools (subfinder, amass, nuclei)"

if [[ $SKIP_GO -eq 0 ]] && command -v go &>/dev/null; then
  GO_VER=$(go version)
  _info "Go: $GO_VER"

  GOPATH="$(go env GOPATH)"
  GO_BIN="$GOPATH/bin"
  export PATH="$PATH:$GO_BIN"

  declare -A GO_TOOLS=(
    [subfinder]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    [nuclei]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    [amass]="github.com/owasp-amass/amass/v4/...@master"
  )

  for tool in subfinder nuclei amass; do
    if command -v "$tool" &>/dev/null; then
      _ok "$tool already installed  →  $(command -v "$tool")"
    else
      _info "Installing $tool …"
      pkg="${GO_TOOLS[$tool]}"
      if [[ $DRY_RUN -eq 0 ]]; then
        if [[ $VERBOSE -ge 1 ]]; then
          go install -v "$pkg" 2>&1 | tail -5 | sed 's/^/    /'
        else
          go install "$pkg" 2>/tmp/go_install_$tool.log
          local_rc=$?
          if [[ $local_rc -ne 0 ]]; then
            _fail "$tool install failed"
            [[ $VERBOSE -eq 0 ]] && cat /tmp/go_install_$tool.log | sed 's/^/    /'
          fi
        fi
        command -v "$tool" &>/dev/null && _ok "$tool installed  →  $(command -v "$tool")" \
          || _fail "$tool binary not found after install"
      else
        _info "[dry-run] go install $pkg"
      fi
    fi
  done

  # Add GO_BIN to PATH permanently
  SHELL_RC=""
  [[ -f "$HOME/.bashrc" ]]  && SHELL_RC="$HOME/.bashrc"
  [[ -f "$HOME/.zshrc"  ]]  && SHELL_RC="$HOME/.zshrc"
  if [[ -n "$SHELL_RC" ]] && ! grep -q "GOPATH/bin" "$SHELL_RC" 2>/dev/null; then
    echo 'export PATH="$PATH:$(go env GOPATH)/bin"' >> "$SHELL_RC"
    _info "Added Go bin to $SHELL_RC"
  fi

elif [[ $SKIP_GO -eq 1 ]]; then
  _skip "Go tools (--no-go flag)"
else
  _fail "Go not installed — subfinder/amass/nuclei unavailable"
  _info "Install Go: https://go.dev/dl/"
fi

# ── Step 7: wpscan ────────────────────────────────────────────────────
_header "WPScan (WordPress Scanner)"

if command -v wpscan &>/dev/null; then
  _ok "wpscan already installed  →  $(command -v wpscan)"
elif command -v gem &>/dev/null; then
  _info "Installing wpscan via gem …"
  _run "wpscan"  gem install wpscan --no-document -q && _ok "wpscan installed" || _fail "wpscan gem install failed"
else
  _fail "ruby/gem not found — wpscan unavailable"
  _info "Install Ruby: sudo apt install ruby-full"
fi

# ── Step 8: Wordlists & config ────────────────────────────────────────
_header "Wordlists & Configuration"

mkdir -p "$SCRIPT_DIR/wordlists" "$SCRIPT_DIR/logs" "$SCRIPT_DIR/reports"

# Subdomain wordlist — pull SecLists if available
SUB_WL="$SCRIPT_DIR/wordlists/subdomains.txt"
if [[ ! -s "$SUB_WL" ]]; then
  SECLISTS_SUBS="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
  if [[ -f "$SECLISTS_SUBS" ]]; then
    cp "$SECLISTS_SUBS" "$SUB_WL"
    _ok "Copied SecLists subdomain wordlist ($(wc -l < "$SUB_WL") words)"
  else
    _info "Generating built-in subdomain wordlist …"
    cat << 'WL' > "$SUB_WL"
www mail remote blog webmail server ns1 ns2 smtp secure vpn api dev staging
test admin portal cdn app ftp ssh mx shop store support help docs wiki status
monitor dashboard login auth accounts internal intranet extranet db database
mysql postgres redis mongo elastic jenkins gitlab jira confluence cloud k8s
docker ci cd build deploy prod beta mobile graphql rest old demo sandbox qa
assets static media images upload backup archive data files download cpanel
WL
    _ok "Built-in wordlist written ($(wc -w < "$SUB_WL") words)"
  fi
fi

# Directory wordlist
DIR_WL="$SCRIPT_DIR/wordlists/directories.txt"
if [[ ! -s "$DIR_WL" ]]; then
  SECLISTS_DIR="/usr/share/seclists/Discovery/Web-Content/common.txt"
  if [[ -f "$SECLISTS_DIR" ]]; then
    cp "$SECLISTS_DIR" "$DIR_WL"
    _ok "Copied SecLists directory wordlist ($(wc -l < "$DIR_WL") entries)"
  else
    _info "Built-in directory wordlist …"
    printf '/admin\n/api\n/login\n/dashboard\n/.git\n/.env\n/backup\n/config\n/wp-admin\n/swagger\n/actuator\n/phpmyadmin\n/graphql\n/server-status\n/health\n' > "$DIR_WL"
    _ok "Built-in directory wordlist written"
  fi
fi

# config.json
CFG="$SCRIPT_DIR/config.json"
if [[ ! -f "$CFG" ]]; then
  cat > "$CFG" << 'JSON'
{
  "_help": "Add your API keys here. Leave empty to skip those features.",
  "shodan_key": "",
  "nvd_key":    "",
  "threads":    10,
  "timeout":    10,
  "rate_limit": 50
}
JSON
  _ok "Default config.json created"
else
  _info "config.json already exists — not overwritten"
fi

# ── Step 9: Wrapper script ────────────────────────────────────────────
_header "CLI Wrapper"

# The packaged CLI ("webosint") is installed by pip as a console script.
# This wrapper is for the standalone legacy scanner only, so it uses a
# distinct name and can never shadow the packaged command.
WRAPPER="/usr/local/bin/webosint-scan"
LEGACY_WRAPPER="/usr/local/bin/webosint"
# Resolve the real absolute path NOW so the wrapper never breaks if moved
REAL_DIR="$(realpath "$SCRIPT_DIR")"
REAL_VENV="$REAL_DIR/venv/bin/activate"
REAL_PY="$REAL_DIR/webosint.py"

_info "Tool path : $REAL_DIR"
_info "Venv path : $REAL_VENV"

if [[ $DRY_RUN -eq 0 ]]; then
  # Use printf to write the wrapper — avoids heredoc expansion pitfalls entirely
  printf '#!/usr/bin/env bash\n' | sudo tee "$WRAPPER" > /dev/null
  printf '# WebOSINT Pro — auto-generated wrapper (do not edit paths manually)\n' | sudo tee -a "$WRAPPER" > /dev/null
  printf 'WEBOSINT_HOME="%s"\n' "$REAL_DIR"                   | sudo tee -a "$WRAPPER" > /dev/null
  printf 'VENV_ACTIVATE="%s"\n' "$REAL_VENV"                  | sudo tee -a "$WRAPPER" > /dev/null
  printf '\n' | sudo tee -a "$WRAPPER" > /dev/null
  printf 'if [[ ! -f "$VENV_ACTIVATE" ]]; then\n'             | sudo tee -a "$WRAPPER" > /dev/null
  printf '  echo "[webosint] ERROR: venv not found at $VENV_ACTIVATE"\n' | sudo tee -a "$WRAPPER" > /dev/null
  printf '  echo "[webosint] Re-run: cd %s && ./install.sh"\n' "$REAL_DIR" | sudo tee -a "$WRAPPER" > /dev/null
  printf '  exit 1\n'                                          | sudo tee -a "$WRAPPER" > /dev/null
  printf 'fi\n\n'                                              | sudo tee -a "$WRAPPER" > /dev/null
  printf 'source "$VENV_ACTIVATE"\n'                          | sudo tee -a "$WRAPPER" > /dev/null
  printf 'exec python3 "%s" "$@"\n' "$REAL_PY"                | sudo tee -a "$WRAPPER" > /dev/null

  sudo chmod +x "$WRAPPER"
  _ok "Wrapper installed : $WRAPPER"

  # Remove a wrapper written by older releases that shadowed the packaged
  # "webosint" command and silently ran the legacy scanner instead.
  if [[ -f "$LEGACY_WRAPPER" ]] && grep -q "auto-generated wrapper" "$LEGACY_WRAPPER" 2>/dev/null; then
    sudo rm -f "$LEGACY_WRAPPER"
    _ok "Removed stale wrapper : $LEGACY_WRAPPER (now provided by pip)"
  fi
  _debug "Wrapper content:"
  [[ $VERBOSE -ge 1 ]] && cat "$WRAPPER" | sed 's/^/    /'
else
  _info "[dry-run] would write $WRAPPER"
  _info "  source $REAL_VENV"
  _info "  exec python3 $REAL_PY"
fi

# ══════════════════════════════════════════════════════════════════════
# Final summary
# ══════════════════════════════════════════════════════════════════════
deactivate 2>/dev/null || true

echo -e "\n${BOLD}${C}══════════════════════════════════════════${RESET}"
echo -e "${BOLD}  Installation Summary${RESET}"
echo -e "${C}══════════════════════════════════════════${RESET}"

echo -e "\n${BOLD}  Tool availability:${RESET}"
for tool in python3 nmap wafw00f subfinder amass nuclei theHarvester wpscan; do
  if command -v "$tool" &>/dev/null; then
    ver=$("$tool" --version 2>&1 | head -1 | tr -d '\n' || echo "")
    echo -e "  ${G}✔${RESET}  ${BOLD}$tool${RESET}  ${DIM}$ver${RESET}"
  else
    echo -e "  ${Y}✗${RESET}  ${DIM}$tool — not found${RESET}"
  fi
done

if [[ ${#ERRORS[@]} -gt 0 ]]; then
  echo -e "\n${BOLD}${R}  Issues encountered:${RESET}"
  for err in "${ERRORS[@]}"; do echo -e "    ${R}✘${RESET} $err"; done
fi

if [[ ${#SKIPPED[@]} -gt 0 ]]; then
  echo -e "\n${DIM}  Skipped: ${SKIPPED[*]}${RESET}"
fi

echo -e "\n${BOLD}  Quick start:${RESET}"
echo -e "  ${C}webosint -t example.com${RESET}                       # default scan"
echo -e "  ${C}webosint -t example.com -v${RESET}                    # verbose: module events"
echo -e "  ${C}webosint -t example.com -vv${RESET}                   # verbose: every request"
echo -e "  ${C}webosint -t example.com -vvv${RESET}                  # verbose: raw headers+body"
echo -e "  ${C}webosint -t example.com --profile aggressive -vv${RESET}"
echo -e "  ${C}webosint -t example.com --modules dns,ssl,mail${RESET}"
echo ""
echo -e "  ${Y}⚠  Only scan systems you own or have written permission to test.${RESET}"
echo -e "${C}══════════════════════════════════════════${RESET}\n"

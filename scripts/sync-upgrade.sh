#!/usr/bin/env bash
#
# WebOSINT Pro - safe in-place upgrade from a release archive.
#
# Unzipping a new release over an existing checkout is unsafe: it overwrites
# changed files but never removes files that were deleted upstream. Stale
# modules and stale tests survive, get imported, and fail in ways that look
# like new bugs. This script mirrors the archive onto the checkout so removals
# are applied too, preserves the virtualenv, generated output, local config and
# git metadata, then restarts the service so no process keeps running the old
# code from memory.
#
# Usage:
#   scripts/sync-upgrade.sh <release.zip>
#   scripts/sync-upgrade.sh <release.zip> --dry-run       preview, writes nothing
#   scripts/sync-upgrade.sh <release.zip> --no-restart
#   scripts/sync-upgrade.sh <release.zip> --service webosint
#
# Requires only python3 and unzip: the recovery path must not depend on tools
# that may be missing on the machine being recovered.
#
set -euo pipefail

ARCHIVE=""
SERVICE="webosint"
DRY_RUN=0
RESTART=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --service) SERVICE="${2:?--service needs a unit name}"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --no-restart) RESTART=0; shift ;;
    -h|--help) sed -n '3,19p' "$0"; exit 0 ;;
    -*) echo "Unknown option: $1" >&2; exit 2 ;;
    *) ARCHIVE="$1"; shift ;;
  esac
done

if [[ -z "${ARCHIVE}" ]]; then
  echo "Usage: $0 <release.zip> [--dry-run] [--no-restart] [--service NAME]" >&2
  exit 2
fi
if [[ ! -f "${ARCHIVE}" ]]; then
  echo "Archive not found: ${ARCHIVE}" >&2
  exit 1
fi
for tool in unzip python3; do
  command -v "${tool}" >/dev/null 2>&1 || {
    echo "Missing required tool: ${tool}" >&2
    exit 1
  }
done

# Resolve the checkout from this script's location, never the caller's cwd.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "${SCRIPT_DIR}/.." && pwd)"

if [[ ! -f "${REPO}/pyproject.toml" ]]; then
  echo "${REPO} does not look like a WebOSINT Pro checkout." >&2
  exit 1
fi

echo "Checkout : ${REPO}"
echo "Archive  : ${ARCHIVE}"

STAGE="$(mktemp -d)"
trap 'rm -rf "${STAGE}"' EXIT

unzip -q "${ARCHIVE}" -d "${STAGE}"

# Release archives contain a single top-level directory; accept either shape.
if [[ -f "${STAGE}/pyproject.toml" ]]; then
  SRC="${STAGE}"
else
  SRC="$(find "${STAGE}" -mindepth 2 -maxdepth 2 -name pyproject.toml -exec dirname {} \; | head -1)"
fi
if [[ -z "${SRC:-}" || ! -f "${SRC}/pyproject.toml" ]]; then
  echo "No pyproject.toml inside the archive; is this a WebOSINT Pro release?" >&2
  exit 1
fi

# The mirror step lives in Python so it can be tested and needs no rsync.
# It protects venv/, .venv/, output/, config.json, .env, .git/ and egg-info.
MIRROR="${SRC}/scripts/sync_upgrade.py"
if [[ ! -f "${MIRROR}" ]]; then
  MIRROR="${SCRIPT_DIR}/sync_upgrade.py"
fi
if [[ ! -f "${MIRROR}" ]]; then
  echo "Cannot find scripts/sync_upgrade.py in the archive or the checkout." >&2
  exit 1
fi

if [[ ${DRY_RUN} -eq 1 ]]; then
  echo
  echo "--- dry run: changes that WOULD be applied ---"
  python3 "${MIRROR}" "${SRC}" "${REPO}" --dry-run
  echo
  echo "Nothing was changed. Re-run without --dry-run to apply."
  exit 0
fi

echo
echo "--- applying ---"
python3 "${MIRROR}" "${SRC}" "${REPO}"

# Byte-compiled files for modules that no longer exist are confusing to read in
# a traceback and importable on some layouts. Drop them.
find "${REPO}" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
find "${REPO}" -name '*.pyc' -delete 2>/dev/null || true

# The output tree is git-ignored, so a release archive never carries it.
mkdir -p "${REPO}/output/reports" "${REPO}/output/logs" "${REPO}/output/cache"

# Reinstall so console scripts and dependency changes take effect. A missing or
# moved virtualenv is the most common cause of an upgrade that looks fine and
# then fails at runtime.
if [[ -x "${REPO}/venv/bin/python" ]]; then
  VENV_PY="${REPO}/venv/bin/python"
elif [[ -x "${REPO}/.venv/bin/python" ]]; then
  VENV_PY="${REPO}/.venv/bin/python"
else
  echo
  echo "No virtualenv found in ${REPO}. Creating one at venv/."
  python3 -m venv "${REPO}/venv"
  VENV_PY="${REPO}/venv/bin/python"
fi

VENV_DIR="$(dirname "$(dirname "${VENV_PY}")")"
echo
echo "--- reinstalling into ${VENV_DIR} ---"
INSTALL_OK=1
# Not fatal: the mirror already succeeded, and aborting here would leave the
# checkout updated but silently un-reinstalled.
"${VENV_PY}" -m pip install --quiet --upgrade pip || INSTALL_OK=0
"${VENV_PY}" -m pip install --quiet -e "${REPO}[all]" || INSTALL_OK=0
if [[ ${INSTALL_OK} -eq 0 ]]; then
  echo "WARNING: pip install did not complete (offline?)." >&2
  echo "Finish it by hand before relying on this install:" >&2
  echo "  ${VENV_PY} -m pip install -e '${REPO}[all]'" >&2
fi

# A long-running service keeps executing the code it loaded at start, from a
# working directory that may no longer exist. Restarting is not optional.
if [[ ${RESTART} -eq 0 ]]; then
  echo
  echo "Skipped restart. If ${SERVICE} is running it is STILL executing the old"
  echo "code: sudo systemctl restart ${SERVICE}"
elif command -v systemctl >/dev/null 2>&1 \
     && systemctl cat "${SERVICE}.service" >/dev/null 2>&1; then
  OLD_PID="$(systemctl show -p MainPID --value "${SERVICE}.service" 2>/dev/null || echo 0)"
  echo
  echo "--- restarting ${SERVICE}.service (was PID ${OLD_PID}) ---"
  if sudo systemctl restart "${SERVICE}.service"; then
    sleep 3
    NEW_PID="$(systemctl show -p MainPID --value "${SERVICE}.service")"
    if [[ "${NEW_PID}" == "0" || "${NEW_PID}" == "${OLD_PID}" ]]; then
      echo "WARNING: ${SERVICE}.service has no new PID; it may be down." >&2
      echo "Diagnose with: journalctl -xeu ${SERVICE} -n 40 --no-pager" >&2
    else
      echo "${SERVICE}.service restarted: PID ${OLD_PID} -> ${NEW_PID}"
      # ExecStart points at a specific interpreter. If the venv was recreated
      # at a different path, the unit must be reinstalled to match.
      if ! systemctl cat "${SERVICE}.service" | grep -q "${VENV_DIR}/bin/python"; then
        echo
        echo "NOTE: the unit does not start ${VENV_DIR}/bin/python." >&2
        echo "Reinstall it so it uses this virtualenv:" >&2
        echo "  sudo -E ./scripts/install-service.sh --lan" >&2
      fi
    fi
  else
    echo "WARNING: restart failed; old code may still be serving requests." >&2
    echo "Diagnose with: journalctl -xeu ${SERVICE} -n 40 --no-pager" >&2
  fi
else
  echo
  echo "No ${SERVICE}.service installed; nothing to restart."
fi

echo
echo "Upgrade complete. Verify with:"
echo "  ${VENV_PY} -m pytest -q"

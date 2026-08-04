#!/usr/bin/env bash
# Install WebOSINT Pro as a systemd service so it starts on boot.
#
#   sudo ./scripts/install-service.sh                 # localhost only
#   sudo ./scripts/install-service.sh --lan           # reachable on your LAN
#   sudo ./scripts/install-service.sh --lan --auth    # LAN + access token
#   sudo ./scripts/install-service.sh --uninstall
#
# Everything after the script name is passed straight through to webserve.py,
# so any flag it accepts works here. Run `python webserve.py --help` to see them.
#
# The unit is named `webosint`, matching `webosint start|stop|status` and the
# `systemctl enable webosint` documented in the README.
set -euo pipefail

SERVICE_NAME="webosint"
LEGACY_NAME="webosint-web"
UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
LEGACY_UNIT_PATH="/etc/systemd/system/${LEGACY_NAME}.service"
WORKDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMPLATE="${WORKDIR}/scripts/webosint.service"

if [[ "${1:-}" == "--uninstall" ]]; then
  systemctl disable --now "${SERVICE_NAME}.service" 2>/dev/null || true
  systemctl disable --now "${LEGACY_NAME}.service" 2>/dev/null || true
  rm -f "${UNIT_PATH}" "${LEGACY_UNIT_PATH}"
  rm -rf "/etc/systemd/system/${SERVICE_NAME}.service.d"
  systemctl daemon-reload
  echo "Removed ${SERVICE_NAME}.service"
  exit 0
fi

if [[ $EUID -ne 0 ]]; then
  echo "This installer writes to ${UNIT_PATH}; re-run it with sudo." >&2
  exit 1
fi

if [[ ! -f "${TEMPLATE}" ]]; then
  echo "Missing unit template: ${TEMPLATE}" >&2
  exit 1
fi

# Run as the invoking user, not root: scans do not need elevated privileges.
RUN_USER="${SUDO_USER:-$(id -un)}"
RUN_GROUP="$(id -gn "${RUN_USER}")"
RUN_HOME="$(getent passwd "${RUN_USER}" | cut -d: -f6)"
RUN_HOME="${RUN_HOME:-/home/${RUN_USER}}"
RUNTIME_DIR="${RUN_HOME}/.webosint"

# Prefer an active virtualenv, then a project one, then the system interpreter.
# VIRTUAL_ENV is forwarded by `sudo -E`; without it we still find .venv/venv.
if [[ -n "${VIRTUAL_ENV:-}" && -x "${VIRTUAL_ENV}/bin/python" ]]; then
  PYTHON="${VIRTUAL_ENV}/bin/python"
elif [[ -x "${WORKDIR}/.venv/bin/python" ]]; then
  PYTHON="${WORKDIR}/.venv/bin/python"
elif [[ -x "${WORKDIR}/venv/bin/python" ]]; then
  PYTHON="${WORKDIR}/venv/bin/python"
else
  PYTHON="$(command -v python3)"
fi

# --lan on its own is not enough: webserve.py refuses a non-loopback bind unless
# --allow-remote is also present. Add it so the documented flag just works.
ARGS="$*"
if [[ " ${ARGS} " == *" --lan "* && " ${ARGS} " != *" --allow-remote "* ]]; then
  ARGS="${ARGS} --allow-remote"
fi

# Every ReadWritePaths entry must exist before systemd builds the namespace,
# otherwise the unit fails with status=226/NAMESPACE.
mkdir -p "${WORKDIR}/reports" "${WORKDIR}/logs" "${RUNTIME_DIR}"
chown -R "${RUN_USER}:${RUN_GROUP}" "${WORKDIR}/reports" "${WORKDIR}/logs" "${RUNTIME_DIR}"
chmod 700 "${RUNTIME_DIR}"

# Retire the old web-only unit if a previous version installed it, so the two
# cannot race for the same port.
if [[ -f "${LEGACY_UNIT_PATH}" ]]; then
  systemctl disable --now "${LEGACY_NAME}.service" 2>/dev/null || true
  rm -f "${LEGACY_UNIT_PATH}"
  echo "Retired the legacy ${LEGACY_NAME}.service"
fi

sed -e "s|__USER__|${RUN_USER}|g" \
    -e "s|__GROUP__|${RUN_GROUP}|g" \
    -e "s|__WORKDIR__|${WORKDIR}|g" \
    -e "s|__HOME__|${RUN_HOME}|g" \
    -e "s|__RUNTIME_DIR__|${RUNTIME_DIR}|g" \
    -e "s|__PYTHON__|${PYTHON}|g" \
    -e "s|__ARGS__|${ARGS}|g" \
    "${TEMPLATE}" > "${UNIT_PATH}"
chmod 644 "${UNIT_PATH}"

systemctl daemon-reload
systemctl enable --now "${SERVICE_NAME}.service"

# Give it a moment to bind before reporting, so a crash loop is not shown as ok.
sleep 2
if systemctl is-active --quiet "${SERVICE_NAME}.service"; then
  echo "Installed and started ${SERVICE_NAME}.service"
else
  echo "Installed ${SERVICE_NAME}.service, but it is NOT running." >&2
  echo "Diagnose with: journalctl -xeu ${SERVICE_NAME} -n 40 --no-pager" >&2
fi

echo "  Runs as     : ${RUN_USER}"
echo "  Python      : ${PYTHON}"
echo "  Working dir : ${WORKDIR}"
echo "  Runtime dir : ${RUNTIME_DIR}"
echo "  Args        : ${ARGS:-<none>}"
echo
if [[ " ${ARGS} " == *" --lan "* ]]; then
  LAN_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
  echo "  Dashboard   : http://${LAN_IP:-<this-host>}:8000"
  echo "  Firewall    : sudo ufw allow from <your-subnet>/24 to any port 8000 proto tcp"
  if [[ " ${ARGS} " != *" --auth "* && " ${ARGS} " != *" --auth-token "* ]]; then
    echo
    echo "  WARNING: the dashboard is reachable on your network with no"
    echo "           authentication. Anyone who can reach this port can launch"
    echo "           scans and read every stored report. Restrict the firewall"
    echo "           rule to trusted hosts, or reinstall with --auth."
  fi
else
  echo "  Dashboard   : http://127.0.0.1:8000 (localhost only; add --lan for network access)"
fi
echo
echo "  Status      : systemctl status ${SERVICE_NAME}    (or: webosint status)"
echo "  Logs        : journalctl -u ${SERVICE_NAME} -f"
echo "  Stop        : sudo systemctl stop ${SERVICE_NAME}"
echo "  Uninstall   : sudo ./scripts/install-service.sh --uninstall"

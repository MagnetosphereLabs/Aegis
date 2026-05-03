#!/usr/bin/env bash
set -euo pipefail

APP_NAME="aegisvault"
APP_DIR="/opt/aegisvault"
BIN_PATH="/usr/local/bin/${APP_NAME}"
CREDSTORE_DIR="/etc/credstore.encrypted"
CRED_NAME_PREFIX="aegisvault-machine-key-"
REPO_SLUG="${REPO_SLUG:-MagnetosphereLabs/Aegis}"
BRANCH="${BRANCH:-main}"
RAW_BASE="${RAW_BASE:-https://raw.githubusercontent.com/${REPO_SLUG}/${BRANCH}}"
ACTION="${1:-install}"
UNINSTALL_MODE="${2:-}"

require_root() {
  if [ "${EUID}" -ne 0 ]; then
    echo "This installer must run as root." >&2
    exit 1
  fi
}

apt_install() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y \
    python3 \
    python3-tk \
    python3-cryptography \
    curl \
    rsync \
    openssh-client \
    tar
}

install_app() {
  mkdir -p "${APP_DIR}"
  local tmp_file
  tmp_file="$(mktemp)"
  
  echo "Downloading update..."
  if ! curl -fsSL "${RAW_BASE}/aegisvault.py" -o "${tmp_file}"; then
    echo "Error: Download failed. Update aborted." >&2
    rm -f "${tmp_file}"
    exit 1
  fi

  # Verify the Python file is fully intact and valid
  if ! python3 -m py_compile "${tmp_file}" >/dev/null 2>&1; then
    echo "Error: Downloaded file is corrupted or incomplete. Update aborted." >&2
    rm -f "${tmp_file}"
    exit 1
  fi

  # Atomic replacement
  mv "${tmp_file}" "${APP_DIR}/aegisvault.py"
  chmod 0755 "${APP_DIR}/aegisvault.py"

  cat > "${BIN_PATH}" <<'EOF'
#!/usr/bin/env bash
exec python3 /opt/aegisvault/aegisvault.py "$@"
EOF
  chmod 0755 "${BIN_PATH}"
}

install_support_files() {
  groupadd -f aegisvault || true
  install -d -m 0750 /var/lib/aegisvault
  install -d -m 0700 "${CREDSTORE_DIR}"
  install -d -m 0750 /var/backups/aegisvault
  install -d -m 0755 /usr/share/applications

  cat > /etc/systemd/system/aegisvault.service <<'EOF'
[Unit]
Description=Aegis backup daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStartPre=/bin/mkdir -p /run/aegisvault
ExecStartPre=/bin/chgrp aegisvault /run/aegisvault
ExecStartPre=/bin/chmod 0770 /run/aegisvault
ExecStart=/usr/local/bin/aegisvault daemon
Restart=on-failure
RestartSec=5
WorkingDirectory=/var/lib/aegisvault
UMask=0077

[Install]
WantedBy=multi-user.target
EOF

  cat > /usr/share/applications/aegisvault.desktop <<'EOF'
[Desktop Entry]
Type=Application
Name=Aegis
Comment=Encrypted Linux backup, restore, and peer sync
Exec=/usr/local/bin/aegisvault gui
Icon=drive-harddisk
Terminal=false
Categories=System;Utility;
StartupNotify=true
EOF

  if [ -n "${SUDO_USER:-}" ] && id "${SUDO_USER}" >/dev/null 2>&1; then
    usermod -aG aegisvault "${SUDO_USER}" || true
  fi

  systemctl daemon-reload
  systemctl enable --now aegisvault.service
}

initialise_app() {
  "${BIN_PATH}" init --repo /var/backups/aegisvault --label "$(hostname)" --encryption on
}

normalise_uninstall_mode() {
  case "${UNINSTALL_MODE:-}" in
    "")
      ;;
    keep|keep-data|app-only)
      UNINSTALL_MODE="keep-data"
      ;;
    purge|full|wipe|wipe-data)
      UNINSTALL_MODE="purge"
      ;;
    *)
      echo "Unknown uninstall mode: ${UNINSTALL_MODE}" >&2
      echo "Use: uninstall, uninstall keep-data, or uninstall purge" >&2
      exit 1
      ;;
  esac
}

prompt_uninstall_mode() {
  normalise_uninstall_mode
  if [ -n "${UNINSTALL_MODE}" ]; then
    return
  fi

  if [ ! -r /dev/tty ]; then
    echo "Uninstall mode is required when no interactive terminal is available." >&2
    echo "Use one of:" >&2
    echo "  uninstall keep-data" >&2
    echo "  uninstall purge" >&2
    exit 1
  fi

  echo >/dev/tty
  echo "Choose uninstall level:" >/dev/tty
  echo "  1) Remove app only (keep settings, encrypted credentials, and backups)" >/dev/tty
  echo "  2) Remove app files and purge all local Aegis data" >/dev/tty
  echo "  3) Cancel" >/dev/tty
  printf "Selection [1-3]: " >/dev/tty

  read -r choice </dev/tty
  case "${choice}" in
    1) UNINSTALL_MODE="keep-data" ;;
    2) UNINSTALL_MODE="purge" ;;
    3)
      echo "Canceled." >/dev/tty
      exit 0
      ;;
    *)
      echo "Invalid selection." >&2
      exit 1
      ;;
  esac
}

read_configured_repo_path() {
  local settings_path="/var/lib/aegisvault/settings.json"

  [ -f "${settings_path}" ] || return 0
  command -v python3 >/dev/null 2>&1 || return 0

  python3 - "${settings_path}" <<'PY'
import json
import sys
from pathlib import Path

p = Path(sys.argv[1])
try:
    data = json.loads(p.read_text(encoding="utf-8"))
except Exception:
    raise SystemExit(0)

repo = str(data.get("repo_path") or "").strip()
if repo:
    print(repo)
PY
}

purge_repo_path_contents() {
  local repo_path="${1:-}"

  [ -n "${repo_path}" ] || return 0

  case "${repo_path}" in
    "/"|"." )
      return 0
      ;;
  esac

  if [ -d "${repo_path}" ]; then
    rm -rf -- "${repo_path}/machines" "${repo_path}/objects"
    rmdir --ignore-fail-on-non-empty -- "${repo_path}" 2>/dev/null || true
  fi
}

do_install() {
  require_root
  apt_install
  install_app
  install_support_files
  initialise_app

  echo
  echo "Aegis installed."
  echo "Command: ${BIN_PATH}"
  echo "Service: systemctl status aegisvault"
  echo "Desktop launcher installed."
  echo "Recovery USB builder available from the Restore tab or: aegisvault create-recovery-usb --device /dev/sdX"
  echo
  echo "IMPORTANT: write down the recovery key when it is shown. It is not written to disk."
  echo "If the desktop app cannot connect right away, log out and back in so the aegisvault group applies to your session."
}

do_update() {
  require_root

  if [ -r /dev/tty ]; then
    echo "Checking system state..." >/dev/tty
  fi

  local lockfile="/var/lib/aegisvault/backup.lock"
  if [ -f "${lockfile}" ]; then
    # flock -n attempts an immediate, non-blocking lock. If it fails, Python is using it.
    if ! flock -n "${lockfile}" -c "true" >/dev/null 2>&1; then
      echo "Error: A backup, restore, or sync job is actively running in the background." >&2
      echo "Wait for the job to finish before updating." >&2
      exit 1
    fi
  fi

  if [ -r /dev/tty ]; then
    echo >/dev/tty
    echo "Aegis update will restart the background service and any open Aegis desktop window." >/dev/tty
    echo "Do not continue if a backup, restore, export, recovery USB job, or peer sync is currently running." >/dev/tty
    printf "Continue with update and restart Aegis now? [y/N]: " >/dev/tty

    local answer=""
    read -r answer </dev/tty
    case "${answer}" in
      y|Y|yes|YES) ;;
      *)
        echo "Update canceled." >/dev/tty
        exit 0
        ;;
    esac
  else
    echo "Refusing to update without an interactive terminal because Aegis must be restarted." >&2
    echo "Run this from a terminal so you can confirm no backup or restore is currently running." >&2
    exit 1
  fi

  local gui_was_running="no"
  if pgrep -f "python3 /opt/aegisvault/aegisvault.py gui" >/dev/null 2>&1; then
    gui_was_running="yes"
    pkill -TERM -f "python3 /opt/aegisvault/aegisvault.py gui" || true
    sleep 1
    pkill -KILL -f "python3 /opt/aegisvault/aegisvault.py gui" || true
  fi

  install_app
  systemctl restart aegisvault.service

  if [ "${gui_was_running}" = "yes" ] && [ -n "${SUDO_USER:-}" ] && id "${SUDO_USER}" >/dev/null 2>&1; then
    local runtime_dir=""
    local sudo_uid=""
    sudo_uid="$(id -u "${SUDO_USER}" 2>/dev/null || true)"
    if [ -n "${sudo_uid}" ] && [ -d "/run/user/${sudo_uid}" ]; then
      runtime_dir="/run/user/${sudo_uid}"
    fi

    runuser -u "${SUDO_USER}" -- env \
      DISPLAY="${DISPLAY:-}" \
      WAYLAND_DISPLAY="${WAYLAND_DISPLAY:-}" \
      XAUTHORITY="${XAUTHORITY:-}" \
      XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-${runtime_dir}}" \
      DBUS_SESSION_BUS_ADDRESS="${DBUS_SESSION_BUS_ADDRESS:-unix:path=${runtime_dir}/bus}" \
      nohup "${BIN_PATH}" gui >/dev/null 2>&1 &
  fi

  echo "Aegis updated. Background service restarted."
  if [ "${gui_was_running}" = "yes" ]; then
    echo "Aegis desktop window was closed and relaunched."
  fi
}

do_uninstall() {
  require_root
  prompt_uninstall_mode

  local configured_repo=""
  configured_repo="$(read_configured_repo_path || true)"

  systemctl disable --now aegisvault.service || true
  rm -f /etc/systemd/system/aegisvault.service
  rm -f /usr/share/applications/aegisvault.desktop
  rm -f "${BIN_PATH}"
  rm -rf "${APP_DIR}"
  rm -rf /run/aegisvault
  systemctl daemon-reload
  systemctl reset-failed aegisvault.service >/dev/null 2>&1 || true

  if [ "${UNINSTALL_MODE}" = "purge" ]; then
    rm -rf /var/lib/aegisvault

    if [ -d "${CREDSTORE_DIR}" ]; then
      find "${CREDSTORE_DIR}" -maxdepth 1 -type f -name "${CRED_NAME_PREFIX}*.cred" -delete
      rmdir --ignore-fail-on-non-empty "${CREDSTORE_DIR}" 2>/dev/null || true
    fi

    purge_repo_path_contents "${configured_repo}"

    if [ -z "${configured_repo}" ] || [ "${configured_repo}" != "/var/backups/aegisvault" ]; then
      purge_repo_path_contents "/var/backups/aegisvault"
    fi

    groupdel aegisvault >/dev/null 2>&1 || true
    echo "Aegis fully removed, including settings, encrypted local unlock credentials, state, and backup repository data."
  else
    echo "Aegis app files removed. Data under /var/lib/aegisvault, the configured backup repo, and ${CREDSTORE_DIR} was left in place."
  fi
}

case "${ACTION}" in
  install) do_install ;;
  update) do_update ;;
  uninstall) do_uninstall ;;
  *)
    echo "Usage: curl ... | sudo bash -s -- {install|update|uninstall} [keep-data|purge]" >&2
    exit 1
    ;;
esac

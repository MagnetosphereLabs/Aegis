#!/usr/bin/env bash
set -euo pipefail

APP_NAME="aegisvault"
APP_DIR="/opt/aegisvault"
BIN_PATH="/usr/local/bin/${APP_NAME}"
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
  curl -fsSL "${RAW_BASE}/aegisvault.py" -o "${APP_DIR}/aegisvault.py"
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
  install -d -m 0750 /var/lib/aegisvault/keys
  install -d -m 0750 /var/backups/aegisvault
  install -d -m 0755 /usr/share/applications

  cat > /etc/systemd/system/aegisvault.service <<'EOF'
[Unit]
Description=AegisVault backup daemon
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
Name=AegisVault
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
  echo "  1) Remove app files only (keep settings, keys, and backups)" >/dev/tty
  echo "  2) Remove app files and purge all local AegisVault data" >/dev/tty
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

do_install() {
  require_root
  apt_install
  install_app
  install_support_files
  initialise_app

  echo
  echo "AegisVault installed."
  echo "Command: ${BIN_PATH}"
  echo "Service: systemctl status aegisvault"
  echo "Desktop launcher installed."
  echo "Recovery USB builder available from the Restore tab or: aegisvault create-recovery-usb --device /dev/sdX"
  echo
  echo "IMPORTANT: move the recovery key file from /var/lib/aegisvault somewhere safe."
  echo "If the desktop app cannot connect right away, log out and back in so the aegisvault group applies to your session."
}

do_update() {
  require_root
  install_app
  systemctl restart aegisvault.service
  echo "AegisVault updated."
}

do_uninstall() {
  require_root
  prompt_uninstall_mode

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
    rm -rf /var/backups/aegisvault
    groupdel aegisvault >/dev/null 2>&1 || true
    echo "AegisVault fully removed, including settings, keys, state, and local backup repository data."
  else
    echo "AegisVault app files removed. Data under /var/lib/aegisvault and /var/backups/aegisvault was left in place."
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

#!/usr/bin/env bash
set -euo pipefail

APP_NAME="aegisvault"
APP_DIR="/opt/aegisvault"
BIN_PATH="/usr/local/bin/${APP_NAME}"
REPO_SLUG="${REPO_SLUG:-YOUR_GITHUB_USERNAME/aegisvault}"
BRANCH="${BRANCH:-main}"
RAW_BASE="${RAW_BASE:-https://raw.githubusercontent.com/${REPO_SLUG}/${BRANCH}}"
ACTION="${1:-install}"

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
  systemctl disable --now aegisvault.service || true
  rm -f /etc/systemd/system/aegisvault.service
  rm -f /usr/share/applications/aegisvault.desktop
  rm -f "${BIN_PATH}"
  rm -rf "${APP_DIR}"
  systemctl daemon-reload
  echo "AegisVault removed. Data under /var/lib/aegisvault and /var/backups/aegisvault was left in place."
}

case "${ACTION}" in
  install) do_install ;;
  update) do_update ;;
  uninstall) do_uninstall ;;
  *)
    echo "Usage: curl ... | sudo bash -s -- {install|update|uninstall}" >&2
    exit 1
    ;;
esac

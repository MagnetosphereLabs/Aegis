#!/usr/bin/env python3
"""
AegisVault
Compact Linux backup app for Debian-based systems.
Single application file with GUI, CLI, daemon, backup engine, restore engine, and peer sync.
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import errno
import fnmatch
import grp
import hashlib
import json
import os
import pwd
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.request
import textwrap
from contextlib import contextmanager
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Set

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import getpass


APP_NAME = "AegisVault"
SOCKET_PATH = "/run/aegisvault/daemon.sock"
VAR_DIR = Path("/var/lib/aegisvault")
CONFIG_PATH = VAR_DIR / "settings.json"
STATE_PATH = VAR_DIR / "state.json"
LEGACY_KEY_DIR = VAR_DIR / "keys"  # for migration from previous versions only, we will never write new keys here
LOCK_PATH = VAR_DIR / "backup.lock"
CREDSTORE_DIR = Path("/etc/credstore.encrypted")
SECURE_TMP_DIR = Path("/dev/shm") if Path("/dev/shm").is_dir() else None
BUNDLE_MAGIC = b"AGBND1"
OBJECT_MAGIC = b"AGOBJ1"
DEFAULT_REPO = "/var/backups/aegisvault"
DEFAULT_CHUNK_MIB = 4
BUFFER_SIZE = 1024 * 1024
LOG_LIMIT = 250
RECOVERY_MARKER = Path("/etc/aegisvault-recovery")
RECOVERY_MOUNT_ROOT = Path("/mnt/aegisvault-recovery")
AUTO_MOUNT_ROOT = Path("/media/aegisvault")
BACKUP_BROWSE_MOUNT_ROOT = Path("/media/aegisvault-browser")
DEFAULT_RECOVERY_SUITE = "bookworm"
DEFAULT_RECOVERY_MIRROR = "https://deb.debian.org/debian"
DEFAULT_REPO_SLUG = "MagnetosphereLabs/Aegis"
MIN_RECOVERY_USB_BYTES = 8 * 1000 * 1000 * 1000


@dataclass
class ScheduleSettings:
    enabled: bool = False
    preset: str = "manual"  # manual, hourly, daily, weekly, custom
    custom_minutes: int = 60

    def interval_minutes(self) -> Optional[int]:
        if not self.enabled:
            return None
        if self.preset == "hourly":
            return 60
        if self.preset == "daily":
            return 60 * 24
        if self.preset == "weekly":
            return 60 * 24 * 7
        if self.preset == "custom":
            return max(5, int(self.custom_minutes))
        return None


@dataclass
class PeerTarget:
    enabled: bool = True
    label: str = ""
    ssh_target: str = ""
    repo_path: str = DEFAULT_REPO
    port: int = 22
    identity_file: str = ""


@dataclass
class Settings:
    version: int = 2
    onboarding_complete: bool = False
    machine_id: str = ""
    machine_label: str = ""
    repo_path: str = DEFAULT_REPO
    encryption_enabled: bool = True
    notifications_enabled: bool = True
    default_backup_profile: str = "both"
    schedule: ScheduleSettings = field(default_factory=ScheduleSettings)
    chunk_size_mib: int = DEFAULT_CHUNK_MIB
    io_yield_ms: int = 2
    apply_packages_on_portable_restore: bool = True
    full_excludes: List[str] = field(default_factory=list)
    portable_includes: List[str] = field(default_factory=list)
    portable_excludes: List[str] = field(default_factory=list)
    peers_enabled: bool = False
    peers: List[PeerTarget] = field(default_factory=list)


@dataclass
class PersistentState:
    last_run_at: str = ""
    last_success_at: str = ""
    last_error: str = ""
    last_sync_at: str = ""
    recovery_key_path: str = ""


@dataclass
class JobState:
    name: str = ""
    stage: str = ""
    started_at: str = ""


@dataclass
class SnapshotMetadata:
    os_release: str = ""
    kernel_release: str = ""
    root_fs: str = ""
    dpkg_query: str = ""
    manual_packages: List[str] = field(default_factory=list)
    portable_manual_packages: List[str] = field(default_factory=list)
    flatpak_packages: List[str] = field(default_factory=list)
    snap_packages: List[str] = field(default_factory=list)
    apt_sources: str = ""
    users: List[str] = field(default_factory=list)
    fstab: str = ""
    hostname_file: str = ""
    hosts_file: str = ""
    machine_id_file: str = ""
    mount_table: str = ""
    partition_table: str = ""
    block_devices_json: str = ""
    root_source: str = ""
    boot_source: str = ""
    efi_source: str = ""
    firmware_mode: str = ""
    notes: List[str] = field(default_factory=list)


@dataclass
class ChunkRef:
    hash: str
    plain_len: int


@dataclass
class SnapshotManifest:
    version: int
    id: str
    run_id: str
    machine_id: str
    machine_label: str
    hostname: str
    created_at: str
    kind: str
    source_paths: List[str]
    exclude_paths: List[str]
    chunk_size: int
    archive_refs: List[ChunkRef]
    archive_plaintext_bytes: int
    archive_sha256: str
    metadata: SnapshotMetadata
    notes: List[str]


@dataclass
class Dashboard:
    settings: Settings
    persistent: PersistentState
    current_job: Optional[JobState]
    snapshots: List[Dict[str, Any]]
    warnings: List[str]
    logs: List[str]


DEFAULT_FULL_EXCLUDES_BASE = [
    "dev",
    "dev/*",
    "proc",
    "proc/*",
    "sys",
    "sys/*",
    "run",
    "run/*",
    "tmp",
    "tmp/*",
    "var/tmp",
    "var/tmp/*",
    "swapfile",
    "media",
    "media/*",
    "mnt",
    "mnt/*",
    "run/media",
    "run/media/*",
]

DEFAULT_PORTABLE_INCLUDES = [
    "home",
    "etc",
    "opt",
    "usr/local",
    "var/lib/flatpak",
    "var/lib/snapd",
    "var/snap",
]

DEFAULT_PORTABLE_EXCLUDES = [
    "etc/fstab",
    "etc/machine-id",
    "etc/hostname",
    "etc/hosts",
    "etc/ssh/ssh_host_*",
    "lib/modules",
    "lib/modules/*",
    "usr/lib/modules",
    "usr/lib/modules/*",
    "var/lib/dkms",
    "var/lib/dkms/*",
    "home/*/.cache",
    "home/*/.cache/*",
    "var/cache",
    "var/cache/*",
]

BACKUP_PROFILE_LABELS = {
    "full_recovery": "Full Machine Backup",
    "portable_state": "Portable Backup",
    "both": "Both backup types",
}

EXTERNAL_BACKUP_ROOT_PREFIXES = ("/media/", "/mnt/", "/run/media/")
SYSTEMD_SERVICE_PATH = Path("/etc/systemd/system/aegisvault.service")


def normalize_backup_profile(value: str) -> str:
    return value if value in BACKUP_PROFILE_LABELS else "both"


def mounted_targets() -> List[str]:
    raw = run_command_optional(["findmnt", "-rn", "-o", "TARGET"])
    return [line.strip() for line in raw.splitlines() if line.strip()]


def is_external_backup_path(repo_path: str) -> bool:
    normalized = os.path.abspath(repo_path).rstrip("/") + "/"
    return normalized.startswith(EXTERNAL_BACKUP_ROOT_PREFIXES)

def prompt_new_recovery_password_cli() -> str:
    if not sys.stdin.isatty():
        raise AegisError(
            "Provide --recovery-password for manual encrypted setup when no desktop env is available."
        )

    first = getpass.getpass("Create a password: ")
    second = getpass.getpass("Confirm your password: ")

    if first != second:
        raise AegisError("Passwords did not match.")

    return validate_recovery_password(first)

def external_mount_present_for_path(repo_path: str) -> bool:
    normalized = os.path.abspath(repo_path)
    for target in sorted(mounted_targets(), key=len, reverse=True):
        if target == "/":
            continue
        cleaned = target.rstrip("/")
        if normalized == cleaned or normalized.startswith(cleaned + "/"):
            if cleaned.startswith(EXTERNAL_BACKUP_ROOT_PREFIXES):
                return True
    return False


def ensure_repo_path_ready(repo_path: str) -> None:
    if is_external_backup_path(repo_path) and not external_mount_present_for_path(repo_path):
        raise AegisError(
            "The selected backup drive is not mounted. Reconnect it and choose the mounted folder again."
        )
    Path(repo_path).mkdir(parents=True, exist_ok=True)

def safe_mount_component(value: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in "-._" else "-" for ch in (value or "").strip())
    cleaned = cleaned.strip(".-")
    return cleaned or "drive"

_UDEVADM_LOCK_SUPPORTED: Optional[bool] = None


def udevadm_lock_supported() -> bool:
    global _UDEVADM_LOCK_SUPPORTED
    if _UDEVADM_LOCK_SUPPORTED is not None:
        return _UDEVADM_LOCK_SUPPORTED

    binary = shutil.which("udevadm")
    if not binary:
        _UDEVADM_LOCK_SUPPORTED = False
        return False

    help_text = run_command_optional([binary, "--help"]).lower()
    _UDEVADM_LOCK_SUPPORTED = (
        "\nlock " in help_text
        or "\n  lock " in help_text
        or " udevadm lock " in help_text
    )
    return _UDEVADM_LOCK_SUPPORTED


def run_blockdev_command(
    cmd: List[str],
    device: str,
    check: bool = True,
    capture: bool = True,
) -> subprocess.CompletedProcess:
    device = ensure_block_device_node(device, timeout_seconds=10)

    if udevadm_lock_supported():
        return run_command(
            ["udevadm", "lock", f"--device={device}", *cmd],
            check=check,
            capture=capture,
        )
    return run_command(cmd, check=check, capture=capture)


def swapoff_device_tree(device: str) -> None:
    disk = device_parent_disk(device) or device
    active_swaps = [
        line.strip()
        for line in run_command_optional(
            ["swapon", "--noheadings", "--raw", "--output", "NAME"]
        ).splitlines()
        if line.strip()
    ]

    for swap_device in active_swaps:
        swap_real = canonical_block_device_path(swap_device)
        if swap_real == disk or device_parent_disk(swap_real) == disk:
            subprocess.run(["swapoff", swap_device], check=False, capture_output=True)

def ensure_traversable_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o755)

def mount_backup_browser_device(device: str) -> str:
    ensure_root()
    device = str(device or "").strip()
    if not device:
        raise AegisError("Choose a drive first.")

    entries = list_block_devices()
    entry = next((item for item in entries if item.get("path") == device), None)
    if not entry or entry.get("type") not in {"part", "disk"}:
        raise AegisError("Choose a mountable drive or partition.")

    existing_mounts = [os.path.abspath(mp) for mp in (entry.get("mountpoints") or []) if mp]
    if existing_mounts:
        return existing_mounts[0]

    fstype = (entry.get("fstype") or "").strip()
    if not fstype or fstype in {"swap", "crypto_LUKS", "LVM2_member"}:
        raise AegisError("That drive is not a mountable filesystem.")

    base_name = safe_mount_component(entry.get("label") or entry.get("name") or Path(device).name)
    ensure_traversable_directory(BACKUP_BROWSE_MOUNT_ROOT)

    mountpoint = BACKUP_BROWSE_MOUNT_ROOT / base_name
    suffix = 2
    while mountpoint.exists():
        if mountpoint.is_mount():
            return str(mountpoint)
        mountpoint = BACKUP_BROWSE_MOUNT_ROOT / f"{base_name}-{suffix}"
        suffix += 1

    ensure_traversable_directory(mountpoint)

    try:
        result = subprocess.run(
            ["mount", device, str(mountpoint)],
            capture_output=True,
            text=True,
            timeout=12,
        )
    except subprocess.TimeoutExpired as exc:
        shutil.rmtree(mountpoint, ignore_errors=True)
        raise AegisError(f"Mount timed out for {device}.") from exc

    if result.returncode != 0:
        shutil.rmtree(mountpoint, ignore_errors=True)
        detail = result.stderr.strip() or result.stdout.strip() or "mount failed"
        raise AegisError(f"Could not mount {device}: {detail}")

    return str(mountpoint)


def discover_backup_location_choices() -> List[Dict[str, str]]:
    choices: List[Dict[str, str]] = []
    seen: Set[str] = set()
    root_disk = current_root_disk()
    entries = list_block_devices()
    entries_by_path = {entry.get("path", ""): entry for entry in entries}

    for entry in entries:
        if entry.get("type") != "part":
            continue

        mountpoints = [os.path.abspath(mp) for mp in (entry.get("mountpoints") or []) if mp]
        if not mountpoints:
            continue

        part_path = entry.get("path", "")
        parent_disk = device_parent_disk(part_path)
        if parent_disk == root_disk:
            continue

        parent_entry = entries_by_path.get(parent_disk, {})
        is_external = (
            bool(entry.get("removable"))
            or entry.get("transport") == "usb"
            or bool(parent_entry.get("removable"))
            or parent_entry.get("transport") == "usb"
            or any(mp.startswith(EXTERNAL_BACKUP_ROOT_PREFIXES) for mp in mountpoints)
        )
        if not is_external:
            continue

        label = entry.get("label") or parent_entry.get("model") or parent_entry.get("serial") or Path(part_path).name
        fs_name = entry.get("fstype") or "unknown fs"
        size_text = human_bytes(int(entry.get("size") or 0))

        for mountpoint in mountpoints:
            root_choice = mountpoint
            app_choice = str(Path(mountpoint) / APP_NAME)

            for path_value, suffix in (
                (root_choice, "use drive root"),
                (app_choice, f"use {APP_NAME} folder"),
            ):
                if path_value in seen:
                    continue
                seen.add(path_value)
                choices.append({
                    "label": f"{label} | {fs_name} | {size_text} | {mountpoint} | {suffix}",
                    "path": path_value,
                })

    return choices


def host_service_unit_text() -> str:
    python_bin = sys.executable
    app_path = str(Path(__file__).resolve())

    load_cred_line = ""
    try:
        settings = load_settings()
        if settings.encryption_enabled:
            load_cred_line = (
                f"LoadCredentialEncrypted="
                f"{credential_name_for_machine(settings.machine_id)}:"
                f"{local_key_credential_path(settings.machine_id)}"
            )
    except Exception:
        pass

    return textwrap.dedent(
        f"""
        [Unit]
        Description=AegisVault background backup daemon
        After=network-online.target local-fs.target
        Wants=network-online.target

        [Service]
        Type=simple
        ExecStartPre=/bin/mkdir -p /run/aegisvault
        ExecStart={python_bin} {app_path} daemon
        Restart=on-failure
        RestartSec=5
        WorkingDirectory=/var/lib/aegisvault
        UMask=0077
        {load_cred_line}

        [Install]
        WantedBy=multi-user.target
        """
    ).strip() + "\n"


def install_or_update_host_service() -> None:
    ensure_root()
    unit_bytes = host_service_unit_text().encode("utf-8")
    current = SYSTEMD_SERVICE_PATH.read_bytes() if SYSTEMD_SERVICE_PATH.exists() else b""
    if current != unit_bytes:
        atomic_write(SYSTEMD_SERVICE_PATH, unit_bytes, mode=0o644)
        run_command(["systemctl", "daemon-reload"], check=False, capture=True)


def desktop_notification_recipients() -> List[Tuple[str, int]]:
    recipients: List[Tuple[str, int]] = []
    run_user_root = Path("/run/user")
    if not run_user_root.exists():
        return recipients

    for child in sorted(run_user_root.iterdir(), key=lambda p: p.name):
        if not child.name.isdigit():
            continue
        uid = int(child.name)
        if uid == 0 or not (child / "bus").exists():
            continue
        try:
            user_name = pwd.getpwuid(uid).pw_name
        except KeyError:
            continue
        recipients.append((user_name, uid))

    return recipients


def send_desktop_notification(title: str, body: str, urgency: str = "normal") -> None:
    binary = shutil.which("notify-send")
    if not binary:
        log_line(f"Desktop notification skipped: {title} — {body}")
        return

    for user_name, uid in desktop_notification_recipients():
        runtime_dir = f"/run/user/{uid}"
        subprocess.run(
            [
                "runuser",
                "-u",
                user_name,
                "--",
                "env",
                f"DBUS_SESSION_BUS_ADDRESS=unix:path={runtime_dir}/bus",
                f"XDG_RUNTIME_DIR={runtime_dir}",
                binary,
                "-a",
                APP_NAME,
                "-u",
                urgency,
                title,
                body,
            ],
            check=False,
            capture_output=True,
            text=True,
        )

class AegisError(Exception):
    pass


class Runtime:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.current_job: Optional[JobState] = None
        self.logs: List[str] = []

RUNTIME = Runtime()
_SOCKET_AUTH_FAILED = False

def now_rfc3339() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def utc_tag() -> str:
    return time.strftime("%Y%m%d-%H%M%S", time.gmtime())


def short_machine(value: str) -> str:
    clean = value.replace("-", "")
    return clean[:8] if clean else "machine"


def random_bytes(length: int) -> bytes:
    return os.urandom(length)


def random_suffix(length: int = 4) -> str:
    return base64.b16encode(os.urandom(length)).decode("ascii").lower()


def machine_id() -> str:
    for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        p = Path(path)
        if p.exists():
            data = p.read_text(encoding="utf-8", errors="ignore").strip()
            if data:
                return data
    return hashlib.sha256(socket.gethostname().encode("utf-8")).hexdigest()


def hostname() -> str:
    return socket.gethostname()


def human_bytes(value: int) -> str:
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    size = float(max(0, value))
    for unit in units:
        if size < 1024.0 or unit == units[-1]:
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} {unit}"
        size /= 1024.0
    return f"{value} B"


def is_recovery_environment() -> bool:
    return RECOVERY_MARKER.exists() or os.environ.get("AEGISVAULT_RECOVERY") == "1"


def firmware_mode() -> str:
    return "uefi" if Path("/sys/firmware/efi").exists() else "bios"


PORTABLE_PACKAGE_EXCLUDE_PATTERNS = [
    "linux-image*",
    "linux-headers*",
    "linux-modules*",
    "linux-tools*",
    "linux-cloud-tools*",
    "linux-generic*",
    "linux-oem*",
    "linux-firmware*",
    "nvidia*",
    "*-dkms",
    "broadcom-sta*",
    "virtualbox-dkms*",
    "zfs-dkms*",
    "grub-*",
    "shim-signed",
    "systemd-boot*",
]


def filter_portable_manual_packages(packages: List[str]) -> List[str]:
    filtered: List[str] = []
    for package in packages:
        if any(fnmatch.fnmatch(package, pattern) for pattern in PORTABLE_PACKAGE_EXCLUDE_PATTERNS):
            continue
        filtered.append(package)
    return filtered


def ensure_root() -> None:
    if os.geteuid() != 0:
        raise AegisError("This operation must be run as root.")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(BUFFER_SIZE)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def local_key_path(machine: str) -> Path:
    # legacy plaintext location; read once for migration, never write new keys here
    return LEGACY_KEY_DIR / f"{machine}.key"


def credential_name_for_machine(machine: str) -> str:
    return f"aegisvault-machine-key-{machine}"


def local_key_credential_path(machine: str) -> Path:
    return CREDSTORE_DIR / f"{credential_name_for_machine(machine)}.cred"


def secure_temp_parent() -> Optional[str]:
    return str(SECURE_TMP_DIR) if SECURE_TMP_DIR else None


def secure_temp_path(prefix: str, suffix: str = "") -> Path:
    fd, tmp_path = tempfile.mkstemp(prefix=prefix, suffix=suffix, dir=secure_temp_parent())
    os.close(fd)
    os.chmod(tmp_path, 0o600)
    return Path(tmp_path)


def ensure_systemd_credential_backend() -> None:
    binary = shutil.which("systemd-creds")
    if not binary:
        raise AegisError(
            "Encrypted unattended local key storage requires systemd-creds. "
            "Do not fall back to a plaintext key file."
        )

    CREDSTORE_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(CREDSTORE_DIR, 0o700)

    secret_path = Path("/var/lib/systemd/credential.secret")
    if not secret_path.exists():
        result = subprocess.run([binary, "setup"], capture_output=True, text=True)
        if result.returncode != 0 and not secret_path.exists():
            detail = result.stderr.strip() or result.stdout.strip() or "systemd-creds setup failed"
            raise AegisError(detail)


def write_machine_key_credential(machine: str, machine_key: bytes) -> None:
    if len(machine_key) != 32:
        raise AegisError("Invalid machine key length.")

    ensure_systemd_credential_backend()
    plain_path = secure_temp_path(".aegisvault-key-", ".bin")
    cred_path = local_key_credential_path(machine)

    try:
        plain_path.write_bytes(machine_key)
        result = subprocess.run(
            [
                "systemd-creds",
                "encrypt",
                f"--name={credential_name_for_machine(machine)}",
                str(plain_path),
                str(cred_path),
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip() or "systemd-creds encrypt failed"
            raise AegisError(detail)
        os.chmod(cred_path, 0o600)
    finally:
        plain_path.unlink(missing_ok=True)


def read_machine_key_credential(machine: str) -> bytes:
    # Preferred path: read the service credential injected by systemd
    service_cred_dir = os.environ.get("CREDENTIALS_DIRECTORY", "").strip()
    if service_cred_dir:
        service_cred = Path(service_cred_dir) / credential_name_for_machine(machine)
        if service_cred.exists():
            data = service_cred.read_bytes()
            if len(data) != 32:
                raise AegisError("Service credential returned an invalid machine key.")
            return data

    # Direct-mode fallback: decrypt the encrypted credential into tmpfs only
    cred_path = local_key_credential_path(machine)
    if not cred_path.exists():
        raise AegisError(f"Encrypted local key credential is missing for {machine}.")

    out_path = secure_temp_path(".aegisvault-key-", ".out")
    try:
        result = subprocess.run(
            [
                "systemd-creds",
                "decrypt",
                f"--name={credential_name_for_machine(machine)}",
                str(cred_path),
                str(out_path),
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip() or "systemd-creds decrypt failed"
            raise AegisError(detail)

        data = out_path.read_bytes()
        if len(data) != 32:
            raise AegisError("Decrypted machine key has an invalid length.")
        return data
    finally:
        out_path.unlink(missing_ok=True)


def has_local_machine_key(machine: str) -> bool:
    service_cred_dir = os.environ.get("CREDENTIALS_DIRECTORY", "").strip()
    if service_cred_dir and (Path(service_cred_dir) / credential_name_for_machine(machine)).exists():
        return True
    return local_key_credential_path(machine).exists() or local_key_path(machine).exists()


def repo_machine_dir(repo: Path, machine: str) -> Path:
    return repo / "machines" / machine


def manifest_path(repo: Path, machine: str, snapshot_id: str) -> Path:
    return repo_machine_dir(repo, machine) / "snapshots" / f"{snapshot_id}.json"


def key_envelope_path(repo: Path, machine: str) -> Path:
    return repo_machine_dir(repo, machine) / "key-envelope.json"


def object_path(repo: Path, machine: str, hash_hex: str) -> Path:
    return repo / "objects" / machine / hash_hex[:2] / f"{hash_hex}.obj"


def normalize_member_path(value: str) -> str:
    return value.lstrip("/").strip()


def split_lines(text: str) -> List[str]:
    return [line.strip() for line in text.splitlines() if line.strip()]


def atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp_path, mode)
        os.replace(tmp_path, path)
    finally:
        try:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
        except FileNotFoundError:
            pass


def save_json(path: Path, payload: Dict[str, Any], mode: int = 0o600) -> None:
    atomic_write(path, json.dumps(payload, indent=2, sort_keys=False).encode("utf-8"), mode=mode)


def load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def default_full_excludes(repo_path: str) -> List[str]:
    values = list(DEFAULT_FULL_EXCLUDES_BASE)
    repo_rel = repo_relative_pattern(repo_path)
    if repo_rel:
        values.extend([repo_rel, f"{repo_rel}/*"])
    return dedupe(values)


def default_portable_includes() -> List[str]:
    return list(DEFAULT_PORTABLE_INCLUDES)


def default_portable_excludes() -> List[str]:
    return list(DEFAULT_PORTABLE_EXCLUDES)


def dedupe(items: List[str]) -> List[str]:
    out: List[str] = []
    seen = set()
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def repo_relative_pattern(repo_path: str) -> str:
    path = Path(repo_path)
    if not path.is_absolute():
        return repo_path.strip("/")
    return str(path).lstrip("/")


def settings_to_dict(settings: Settings) -> Dict[str, Any]:
    return asdict(settings)


def settings_from_dict(data: Dict[str, Any]) -> Settings:
    schedule_data = data.get("schedule") or {}
    peers_data = data.get("peers") or []

    settings = Settings(
        version=int(data.get("version", 2)),
        onboarding_complete=bool(data.get("onboarding_complete", False)),
        machine_id=str(data.get("machine_id") or machine_id()),
        machine_label=str(data.get("machine_label") or hostname()),
        repo_path=str(data.get("repo_path") or DEFAULT_REPO),
        encryption_enabled=bool(data.get("encryption_enabled", True)),
        notifications_enabled=bool(data.get("notifications_enabled", True)),
        default_backup_profile=normalize_backup_profile(str(data.get("default_backup_profile") or "both")),
        schedule=ScheduleSettings(
            enabled=bool(schedule_data.get("enabled", False)),
            preset=str(schedule_data.get("preset", "manual")),
            custom_minutes=int(schedule_data.get("custom_minutes", 60)),
        ),
        chunk_size_mib=int(data.get("chunk_size_mib", DEFAULT_CHUNK_MIB)),
        io_yield_ms=int(data.get("io_yield_ms", 2)),
        apply_packages_on_portable_restore=bool(data.get("apply_packages_on_portable_restore", True)),
        full_excludes=list(data.get("full_excludes") or []),
        portable_includes=list(data.get("portable_includes") or []),
        portable_excludes=list(data.get("portable_excludes") or []),
        peers_enabled=bool(data.get("peers_enabled", False)),
        peers=[
            PeerTarget(
                enabled=bool(peer.get("enabled", True)),
                label=str(peer.get("label", "")),
                ssh_target=str(peer.get("ssh_target", "")),
                repo_path=str(peer.get("repo_path") or DEFAULT_REPO),
                port=int(peer.get("port", 22)),
                identity_file=str(peer.get("identity_file") or ""),
            )
            for peer in peers_data
        ],
    )

    if not settings.machine_id:
        settings.machine_id = machine_id()
    if not settings.machine_label:
        settings.machine_label = hostname()
    if not settings.full_excludes:
        settings.full_excludes = default_full_excludes(settings.repo_path)
    if not settings.portable_includes:
        settings.portable_includes = default_portable_includes()
    if not settings.portable_excludes:
        settings.portable_excludes = default_portable_excludes()

    return settings


def persistent_state_from_dict(data: Dict[str, Any]) -> PersistentState:
    return PersistentState(
        last_run_at=str(data.get("last_run_at", "")),
        last_success_at=str(data.get("last_success_at", "")),
        last_error=str(data.get("last_error", "")),
        last_sync_at=str(data.get("last_sync_at", "")),
        recovery_key_path=str(data.get("recovery_key_path", "")),
    )


def persistent_state_to_dict(state: PersistentState) -> Dict[str, Any]:
    return asdict(state)


def load_settings() -> Settings:
    if not CONFIG_PATH.exists():
        settings = Settings(
            onboarding_complete=False,
            machine_id=machine_id(),
            machine_label=hostname(),
            repo_path=DEFAULT_REPO,
            encryption_enabled=True,
            full_excludes=default_full_excludes(DEFAULT_REPO),
            portable_includes=default_portable_includes(),
            portable_excludes=default_portable_excludes(),
        )
        return settings
    return settings_from_dict(load_json(CONFIG_PATH))


def save_settings(settings: Settings) -> None:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    save_json(CONFIG_PATH, settings_to_dict(settings), mode=0o600)


def load_state() -> PersistentState:
    if not STATE_PATH.exists():
        return PersistentState()
    return persistent_state_from_dict(load_json(STATE_PATH))


def save_state(state: PersistentState) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    save_json(STATE_PATH, persistent_state_to_dict(state), mode=0o600)


def log_line(message: str) -> None:
    stamp = now_rfc3339()
    line = f"[{stamp}] {message}"
    with RUNTIME.lock:
        RUNTIME.logs.append(line)
        if len(RUNTIME.logs) > LOG_LIMIT:
            RUNTIME.logs = RUNTIME.logs[-LOG_LIMIT:]


def update_stage(stage: str) -> None:
    with RUNTIME.lock:
        if RUNTIME.current_job:
            RUNTIME.current_job.stage = stage
    log_line(stage)

def run_command(cmd: List[str], check: bool = True, capture: bool = True, cwd: Optional[Path] = None) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            check=check,
            capture_output=capture,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        parts: List[str] = []
        if exc.stdout and exc.stdout.strip():
            parts.append(exc.stdout.strip())
        if exc.stderr and exc.stderr.strip():
            parts.append(exc.stderr.strip())
        detail = "\n".join(parts).strip()
        cmd_text = " ".join(exc.cmd)
        raise AegisError(f"{cmd_text} failed: {detail or f'exit status {exc.returncode}'}") from exc


def run_command_optional(cmd: List[str]) -> str:
    try:
        result = run_command(cmd, check=True, capture=True)
        return result.stdout.strip()
    except Exception:
        return ""


def safe_read_text(path: str) -> str:
    p = Path(path)
    if not p.exists():
        return ""
    try:
        return p.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def blkid_value(device: str, field: str) -> str:
    return run_command_optional(["blkid", "-s", field, "-o", "value", device]).strip()

def disk_partition_path(device: str, number: int) -> str:
    if device.startswith("/dev/disk/by-id/") or device.startswith("/dev/disk/by-path/"):
        return f"{device}-part{number}"

    base = Path(device).name
    suffix = f"p{number}" if base[-1:].isdigit() else str(number)
    return f"{device}{suffix}"


def current_root_source() -> str:
    return run_command_optional(["findmnt", "-nro", "SOURCE", "/"]).strip()


def device_parent_disk(device: str) -> str:
    device = device.strip()
    if not device:
        return ""
    dev_type = run_command_optional(["lsblk", "-ndo", "TYPE", device]).strip()
    if dev_type == "disk":
        return device
    parent = run_command_optional(["lsblk", "-ndo", "PKNAME", device]).strip()
    if parent:
        return f"/dev/{parent}"
    return device


def current_root_disk() -> str:
    return device_parent_disk(current_root_source())


def list_block_devices() -> List[Dict[str, Any]]:
    raw = run_command_optional([
        "lsblk", "-J", "-b",
        "-o",
        "NAME,PATH,TYPE,SIZE,RM,RO,TRAN,MODEL,SERIAL,FSTYPE,LABEL,UUID,PARTUUID,PKNAME,PARTN,MOUNTPOINTS",
    ])
    if not raw:
        return []
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return []

    out: List[Dict[str, Any]] = []

    def walk(node: Dict[str, Any]) -> None:
        mountpoints = [mp for mp in (node.get("mountpoints") or []) if mp]
        entry = {
            "name": node.get("name", ""),
            "path": node.get("path", ""),
            "type": node.get("type", ""),
            "size": int(node.get("size") or 0),
            "removable": bool(node.get("rm", False)),
            "read_only": bool(node.get("ro", False)),
            "transport": node.get("tran") or "",
            "model": (node.get("model") or "").strip(),
            "serial": (node.get("serial") or "").strip(),
            "fstype": node.get("fstype") or "",
            "label": node.get("label") or "",
            "uuid": node.get("uuid") or "",
            "partuuid": node.get("partuuid") or "",
            "pkname": node.get("pkname") or "",
            "partn": int(node.get("partn") or 0),
            "mountpoints": mountpoints,
        }
        out.append(entry)
        for child in node.get("children") or []:
            walk(child)

    for node in payload.get("blockdevices") or []:
        walk(node)
    return out


def canonical_block_device_path(device: str) -> str:
    value = str(device or "").strip()
    if not value:
        return ""
    return os.path.realpath(value)

def block_device_symlink_candidates(device: str) -> List[str]:
    real = canonical_block_device_path(device)
    if not real:
        return []

    found: List[str] = []
    for root in (Path("/dev/disk/by-id"), Path("/dev/disk/by-path")):
        if not root.is_dir():
            continue
        for child in sorted(root.iterdir()):
            if "-part" in child.name:
                continue
            try:
                if os.path.realpath(str(child)) == real:
                    found.append(str(child))
            except OSError:
                continue

    return dedupe(
        sorted(
            found,
            key=lambda p: (
                "/by-id/" not in p,
                "wwn-" not in Path(p).name,
                len(Path(p).name),
                p,
            ),
        )
    )


def stable_disk_device_path(device: str) -> str:
    real = canonical_block_device_path(device)
    if not real:
        return ""
    candidates = block_device_symlink_candidates(real)
    return candidates[0] if candidates else real


def observed_block_device_size_bytes(device: str) -> int:
    real = canonical_block_device_path(device)
    if not real:
        return 0

    sizes: List[int] = []

    blockdev_text = run_command_optional(["blockdev", "--getsize64", real]).strip()
    if blockdev_text.isdigit():
        sizes.append(int(blockdev_text))

    entry = find_block_device_entry(real) or {}
    entry_size = int(entry.get("size") or 0)
    if entry_size > 0:
        sizes.append(entry_size)

    sysfs_size_path = Path("/sys/class/block") / Path(real).name / "size"
    if sysfs_size_path.exists():
        try:
            raw = sysfs_size_path.read_text(encoding="utf-8", errors="ignore").strip()
            if raw.isdigit():
                sizes.append(int(raw) * 512)
        except Exception:
            pass

    positive = [value for value in sizes if value > 0]
    # During USB repartition/rescan, one observer can lag low briefly.
    # Do not let a single stale size veto a sane current device.
    return max(positive) if positive else 0

def _usable_block_device_node(path: Path, expected_major: int, expected_minor: int) -> bool:
    try:
        st = os.stat(path)
    except OSError:
        return False

    if not stat.S_ISBLK(st.st_mode):
        return False

    if os.major(st.st_rdev) != expected_major or os.minor(st.st_rdev) != expected_minor:
        return False

    fd = -1
    try:
        fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        return True
    except OSError as exc:
        if exc.errno in (errno.ENXIO, errno.ENODEV, errno.ENOENT):
            return False
        raise
    finally:
        if fd >= 0:
            os.close(fd)


def ensure_block_device_node(device: str, timeout_seconds: int = 10) -> str:
    requested = str(device or "").strip()
    if not requested:
        raise AegisError("Missing block device path.")

    candidate = canonical_block_device_path(requested) or requested
    name = Path(candidate).name
    sysfs = Path("/sys/class/block") / name
    if not sysfs.exists():
        raise AegisError(f"{requested} is not currently present in sysfs.")

    dev_text = (sysfs / "dev").read_text(encoding="utf-8", errors="ignore").strip()
    if ":" not in dev_text:
        raise AegisError(f"Could not read major:minor for {requested} from sysfs.")

    major_text, minor_text = dev_text.split(":", 1)
    if not major_text.isdigit() or not minor_text.isdigit():
        raise AegisError(f"Could not parse major:minor for {requested} from sysfs.")

    expected_major = int(major_text)
    expected_minor = int(minor_text)
    devnode = Path("/dev") / name

    if _usable_block_device_node(devnode, expected_major, expected_minor):
        return str(devnode)

    udevadm = shutil.which("udevadm")
    if udevadm:
        subprocess.run(
            [udevadm, "trigger", "--action=add", str(sysfs)],
            check=False,
            capture_output=True,
        )
        subprocess.run([udevadm, "settle"], check=False, capture_output=True)

        # Newer systemd has "udevadm wait", which is even better after device churn.
        wait_help = run_command_optional([udevadm, "--help"]).lower()
        if "\nwait " in wait_help or "\n  wait " in wait_help or " udevadm wait " in wait_help:
            subprocess.run(
                [udevadm, "wait", "--settle", "--initialized=no", "-t", str(timeout_seconds), str(devnode)],
                check=False,
                capture_output=True,
            )

    deadline = time.time() + max(1, timeout_seconds)
    while time.time() < deadline:
        if _usable_block_device_node(devnode, expected_major, expected_minor):
            return str(devnode)
        time.sleep(0.2)

    try:
        if devnode.exists() or devnode.is_symlink():
            devnode.unlink()
    except FileNotFoundError:
        pass

    os.mknod(
        devnode,
        stat.S_IFBLK | 0o600,
        os.makedev(expected_major, expected_minor),
    )

    if _usable_block_device_node(devnode, expected_major, expected_minor):
        return str(devnode)

    raise AegisError(
        f"{requested} exists in sysfs as {name}, but Linux did not provide a usable block-device node."
    )


_UDEVADM_WAIT_SUPPORTED: Optional[bool] = None


def udevadm_wait_supported() -> bool:
    global _UDEVADM_WAIT_SUPPORTED
    if _UDEVADM_WAIT_SUPPORTED is not None:
        return _UDEVADM_WAIT_SUPPORTED

    binary = shutil.which("udevadm")
    if not binary:
        _UDEVADM_WAIT_SUPPORTED = False
        return False

    help_text = run_command_optional([binary, "--help"]).lower()
    _UDEVADM_WAIT_SUPPORTED = (
        "\nwait " in help_text
        or "\n  wait " in help_text
        or " udevadm wait " in help_text
    )
    return _UDEVADM_WAIT_SUPPORTED


def wait_for_udev_device(path: str, timeout_seconds: int = 10, initialized: bool = False) -> None:
    path = str(path or "").strip()
    udevadm = shutil.which("udevadm")
    if not path or not udevadm:
        return

    if udevadm_wait_supported():
        subprocess.run(
            [
                udevadm,
                "wait",
                "--settle",
                f"--initialized={'yes' if initialized else 'no'}",
                "-t",
                str(max(1, timeout_seconds)),
                path,
            ],
            check=False,
            capture_output=True,
        )
    else:
        subprocess.run([udevadm, "settle"], check=False, capture_output=True)


def udev_device_properties(device: str) -> Dict[str, str]:
    udevadm = shutil.which("udevadm")
    real = canonical_block_device_path(device)
    if not udevadm or not real:
        return {}

    output = run_command_optional([udevadm, "info", "--query=property", "--name", real])
    props: Dict[str, str] = {}
    for line in output.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        props[key] = value
    return props


def block_device_sysfs_identity_path(device: str) -> str:
    real = canonical_block_device_path(device)
    if not real:
        return ""

    path = Path("/sys/class/block") / Path(real).name / "device"
    try:
        if path.exists():
            return os.path.realpath(str(path))
    except OSError:
        pass
    return ""


def block_device_devtype(device: str) -> str:
    real = canonical_block_device_path(device)
    if not real:
        return ""

    sysfs = Path("/sys/class/block") / Path(real).name
    if not sysfs.exists():
        return ""

    return "part" if (sysfs / "partition").exists() else "disk"


def block_device_read_only(device: str) -> bool:
    real = canonical_block_device_path(device)
    if not real:
        return False

    ro_path = Path("/sys/class/block") / Path(real).name / "ro"
    try:
        return ro_path.read_text(encoding="utf-8", errors="ignore").strip() == "1"
    except Exception:
        return False


def best_effort_block_device_rescan(device: str) -> None:
    real = canonical_block_device_path(device)
    if not real:
        return

    rescan_path = Path("/sys/class/block") / Path(real).name / "device" / "rescan"
    try:
        if rescan_path.exists():
            rescan_path.write_text("1\n", encoding="utf-8")
    except Exception:
        pass


def recover_block_device_state(device: str, allow_rescan: bool = True) -> None:
    try:
        real = ensure_block_device_node(device, timeout_seconds=1)
    except AegisError:
        real = canonical_block_device_path(device) or str(device or "").strip()

    if not real:
        return

    if Path(real).exists():
        subprocess.run(["sync"], check=False, capture_output=True)
        subprocess.run(["blockdev", "--flushbufs", real], check=False, capture_output=True)
        subprocess.run(["blockdev", "--rereadpt", real], check=False, capture_output=True)
        subprocess.run(["partprobe", real], check=False, capture_output=True)
        subprocess.run(["partx", "-u", real], check=False, capture_output=True)

        if allow_rescan:
            best_effort_block_device_rescan(real)

        sysfs = Path("/sys/class/block") / Path(real).name
        if shutil.which("udevadm") and sysfs.exists():
            subprocess.run(
                ["udevadm", "trigger", "--action=change", str(sysfs)],
                check=False,
                capture_output=True,
            )

    wait_for_udev_device(real, timeout_seconds=3, initialized=False)
    subprocess.run(["udevadm", "settle"], check=False, capture_output=True)

    
def partition_path_for_number(device: str, number: int, timeout_seconds: int = 30) -> str:
    disk = ensure_block_device_node(device, timeout_seconds=10)
    expected = disk_partition_path(disk, number)
    disk_name = Path(disk).name
    deadline = time.time() + timeout_seconds

    while time.time() < deadline:
        wait_for_udev_device(expected, timeout_seconds=2, initialized=False)
        try:
            part_node = ensure_block_device_node(expected, timeout_seconds=2)
        except AegisError:
            part_node = ""

        if part_node and block_device_devtype(part_node) == "part":
            return part_node

        recover_block_device_state(disk, allow_rescan=True)

        for entry in list_block_devices():
            if entry.get("type") != "part":
                continue
            if str(entry.get("pkname") or "") != disk_name:
                continue
            if int(entry.get("partn") or 0) != number:
                continue

            part_path = str(entry.get("path") or "").strip()
            if part_path:
                return ensure_block_device_node(part_path, timeout_seconds=10)

        time.sleep(0.5)

    raise AegisError(f"Partition {number} did not appear on {disk}.")

def wait_for_expected_disk_size(device: str, expected_size: int, timeout_seconds: int = 25) -> int:
    requested = str(device or "").strip()
    end = time.time() + timeout_seconds
    last_seen = 0

    minimum_acceptable = (
        max(expected_size - (64 * 1024 * 1024), expected_size // 2)
        if expected_size > 0
        else 64 * 1024 * 1024
    )

    while time.time() < end:
        try:
            real = ensure_block_device_node(requested, timeout_seconds=3)
        except AegisError:
            recover_block_device_state(requested, allow_rescan=True)
            try:
                real = ensure_block_device_node(requested, timeout_seconds=3)
            except AegisError:
                real = canonical_block_device_path(requested) or requested

        wait_for_udev_device(real, timeout_seconds=3, initialized=False)
        subprocess.run(["udevadm", "settle"], check=False, capture_output=True)

        last_seen = observed_block_device_size_bytes(real)
        if last_seen >= minimum_acceptable:
            return last_seen

        recover_block_device_state(real, allow_rescan=True)
        time.sleep(0.5)

    expected_text = human_bytes(expected_size) if expected_size > 0 else "its expected size"
    seen_text = human_bytes(last_seen) if last_seen > 0 else "0 B"
    raise AegisError(
        f"{requested} is still reporting an invalid transient size ({seen_text}) instead of {expected_text}. "
        "AegisVault already tried partition-table rereads, udev reprocessing, and a per-device rescan before giving up."
    )


def capture_block_device_identity(device: str) -> Dict[str, Any]:
    entry = find_block_device_entry(device) or {}
    stable = stable_disk_device_path(device)
    lookup_device = stable or device
    observed_size = observed_block_device_size_bytes(lookup_device)
    props = udev_device_properties(lookup_device)

    return {
        "requested_path": str(device or "").strip(),
        "stable_path": stable if stable.startswith("/dev/disk/") else "",
        "real_path": canonical_block_device_path(device),
        "sysfs_device": block_device_sysfs_identity_path(lookup_device),
        "id_serial": str(props.get("ID_SERIAL") or ""),
        "id_serial_short": str(props.get("ID_SERIAL_SHORT") or ""),
        "id_wwn": str(props.get("ID_WWN_WITH_EXTENSION") or props.get("ID_WWN") or ""),
        "id_path": str(props.get("ID_PATH") or ""),
        "serial": str(entry.get("serial") or ""),
        "model": str(entry.get("model") or ""),
        "size": observed_size or int(entry.get("size") or 0),
        "transport": str(entry.get("transport") or ""),
        "removable": bool(entry.get("removable", False)),
    }

def _entry_identity_score(entry: Dict[str, Any], identity: Dict[str, Any]) -> int:
    path = str(entry.get("path") or "").strip()
    if not path:
        return 0

    score = 0
    props = udev_device_properties(path)

    if identity.get("sysfs_device") and block_device_sysfs_identity_path(path) == str(identity.get("sysfs_device")):
        score += 1000

    if identity.get("id_wwn"):
        current_wwn = str(props.get("ID_WWN_WITH_EXTENSION") or props.get("ID_WWN") or "")
        if current_wwn == str(identity.get("id_wwn")):
            score += 900

    if identity.get("id_serial_short"):
        if str(props.get("ID_SERIAL_SHORT") or "") == str(identity.get("id_serial_short")):
            score += 800

    if identity.get("id_serial"):
        if str(props.get("ID_SERIAL") or "") == str(identity.get("id_serial")):
            score += 700

    if identity.get("id_path"):
        if str(props.get("ID_PATH") or "") == str(identity.get("id_path")):
            score += 600

    if identity.get("serial"):
        if str(entry.get("serial") or "") == str(identity.get("serial")):
            score += 500

    if identity.get("model"):
        if str(entry.get("model") or "") == str(identity.get("model")):
            score += 100

    if identity.get("transport"):
        if str(entry.get("transport") or "") == str(identity.get("transport")):
            score += 50

    if "removable" in identity and bool(entry.get("removable", False)) == bool(identity.get("removable", False)):
        score += 10

    return score


def resolve_block_device_from_identity(identity: Dict[str, Any], timeout_seconds: int = 20) -> str:
    deadline = time.time() + max(1, timeout_seconds)
    last_seen_path = ""

    while time.time() < deadline:
        subprocess.run(["udevadm", "settle"], check=False, capture_output=True)

        direct_candidates = dedupe([
            str(identity.get("stable_path") or "").strip(),
            str(identity.get("requested_path") or "").strip(),
            str(identity.get("real_path") or "").strip(),
        ])

        # First try the exact device node/symlink we already know about.
        # If that fails, try to heal it before giving up on that path.
        for candidate in direct_candidates:
            if not candidate:
                continue

            wait_for_udev_device(candidate, timeout_seconds=1, initialized=False)

            try:
                node = ensure_block_device_node(candidate, timeout_seconds=2)
            except AegisError:
                recover_block_device_state(candidate, allow_rescan=True)
                try:
                    node = ensure_block_device_node(candidate, timeout_seconds=3)
                except AegisError:
                    continue

            if block_device_devtype(node) not in {"", "disk"}:
                continue
            if block_device_read_only(node):
                continue

            return node

        # If the kernel renumbered the disk, score current disks by strong
        # sysfs/udev identity signals and only auto-pick unambiguous matches.
        scored_matches: List[Tuple[int, str]] = []
        for entry in list_block_devices():
            if entry.get("type") != "disk":
                continue
            if bool(entry.get("read_only")):
                continue

            path = str(entry.get("path") or "").strip()
            if not path:
                continue

            score = _entry_identity_score(entry, identity)
            if score <= 0:
                continue

            scored_matches.append((score, path))

        if scored_matches:
            scored_matches.sort(key=lambda item: (item[0], item[1]), reverse=True)
            top_score, top_path = scored_matches[0]
            second_score = scored_matches[1][0] if len(scored_matches) > 1 else -1

            if top_score > 0 and top_score > second_score:
                try:
                    node = ensure_block_device_node(top_path, timeout_seconds=3)
                except AegisError:
                    recover_block_device_state(top_path, allow_rescan=True)
                    try:
                        node = ensure_block_device_node(top_path, timeout_seconds=5)
                    except AegisError:
                        node = ""

                if node and block_device_devtype(node) in {"", "disk"} and not block_device_read_only(node):
                    return node

                if node:
                    last_seen_path = node

        # Keep nudging only the selected target disk identity, not the whole host.
        for candidate in dedupe([last_seen_path] + direct_candidates):
            if candidate:
                recover_block_device_state(candidate, allow_rescan=True)

        time.sleep(0.5)

    label = (
        str(identity.get("stable_path") or "").strip()
        or str(identity.get("requested_path") or "").strip()
        or str(identity.get("real_path") or "").strip()
        or "the selected USB disk"
    )
    raise AegisError(
        f"{label} did not come back as a usable whole-disk device after the kernel updated block devices. "
        "AegisVault tried udev settle/wait, partition-table rereads, partprobe, partx, and a per-device rescan. "
        "If the stick is still present, Linux either renumbered it ambiguously or the device itself stopped responding."
    )

def find_block_device_entry(device: str) -> Optional[Dict[str, Any]]:
    wanted = canonical_block_device_path(device)
    if not wanted:
        return None

    for entry in list_block_devices():
        entry_path = canonical_block_device_path(entry.get("path", ""))
        if entry_path == wanted:
            return entry
    return None

def list_disk_choices(exclude_paths: Optional[Set[str]] = None, removable_only: bool = False) -> List[Dict[str, Any]]:
    exclude_paths = exclude_paths or set()
    items: List[Dict[str, Any]] = []
    for entry in list_block_devices():
        if entry.get("type") != "disk":
            continue
        if entry.get("path") in exclude_paths:
            continue
        if removable_only and not (entry.get("removable") or entry.get("transport") == "usb"):
            continue
        label = entry.get("model") or entry.get("serial") or entry.get("name")
        items.append({
            **entry,
            "display": f"{entry.get('path')}  |  {label}  |  {human_bytes(int(entry.get('size') or 0))}",
        })
    return items


def discover_repo_candidates() -> List[str]:
    candidates: List[str] = []
    seen: Set[str] = set()
    search_roots = [Path("/media"), Path("/mnt"), Path("/run/media")]
    current = Path(load_settings().repo_path)
    if current.exists():
        search_roots.insert(0, current)
    for root in search_roots:
        if not root.exists():
            continue
        roots_to_scan = [root] if root.is_dir() else []
        for base in roots_to_scan:
            for candidate in [base] + [p for p in base.glob("*") if p.is_dir()] + [p for p in base.glob("*/*") if p.is_dir()]:
                if candidate in seen:
                    continue
                seen.add(str(candidate))
                if (candidate / "machines").is_dir() and (candidate / "objects").is_dir():
                    candidates.append(str(candidate))
    return dedupe(candidates)


def unmount_device_tree(device: str) -> None:
    paths = []
    for entry in list_block_devices():
        if entry.get("path") == device or device_parent_disk(entry.get("path", "")) == device:
            paths.extend(entry.get("mountpoints") or [])
    for mount_path in sorted({p for p in paths if p}, key=len, reverse=True):
        subprocess.run(["umount", "-lf", mount_path], check=False, capture_output=True)


def auto_mount_recovery_sources() -> List[str]:
    if not is_recovery_environment():
        return []
    mounted: List[str] = []
    root_disk = current_root_disk()
    AUTO_MOUNT_ROOT.mkdir(parents=True, exist_ok=True)
    for entry in list_block_devices():
        if entry.get("type") != "part":
            continue
        if entry.get("mountpoints"):
            continue
        parent = device_parent_disk(entry.get("path", ""))
        if parent == root_disk:
            continue
        fstype = entry.get("fstype") or ""
        if not fstype or fstype in {"swap", "crypto_LUKS", "LVM2_member"}:
            continue
        mountpoint = AUTO_MOUNT_ROOT / entry.get("name", "disk")
        mountpoint.mkdir(parents=True, exist_ok=True)
        result = subprocess.run(["mount", "-o", "ro", entry["path"], str(mountpoint)], capture_output=True, text=True)
        if result.returncode == 0:
            mounted.append(str(mountpoint))
    return mounted


def ensure_host_packages(packages: List[str]) -> None:
    missing: List[str] = []
    for package in packages:
        status = subprocess.run(["dpkg", "-s", package], capture_output=True, text=True)
        if status.returncode != 0:
            missing.append(package)
    if not missing:
        return
    update_stage("Installing required host packages")
    run_command(["apt-get", "update"], check=True, capture=True)
    run_command(["apt-get", "install", "-y", *missing], check=True, capture=True)


def ensure_recovery_builder_prereqs() -> None:
    ensure_host_packages([
        "debootstrap",
        "parted",
        "fdisk",
        "dosfstools",
        "gdisk",
        "grub-pc-bin",
        "grub-efi-amd64-bin",
        "ca-certificates",
    ])


def assert_safe_target_disk(device: str) -> str:
    requested = str(device or "").strip()
    real_device = canonical_block_device_path(requested)
    if not real_device:
        raise AegisError("Choose a whole-disk device first.")

    entry = find_block_device_entry(real_device)
    if not entry:
        raise AegisError(
            f"{requested or real_device} is not currently available. Reconnect it, click Refresh, and try again."
        )

    if entry.get("type") != "disk":
        parent = device_parent_disk(real_device)
        example = parent if parent and parent != real_device else "/dev/sdb"
        raise AegisError(f"Choose a whole-disk device like {example}, not {requested or real_device}.")

    if bool(entry.get("read_only")):
        raise AegisError(
            f"{requested or real_device} is read-only. Disable any write-protect switch or choose another drive."
        )

    if real_device == current_root_disk():
        raise AegisError("Refusing to operate on the disk hosting the currently booted system.")

    identity = capture_block_device_identity(real_device)
    return resolve_block_device_from_identity(identity, timeout_seconds=30)


RECOVERY_PASSWORD_REQUIRED_ERROR = (
    "A password is required when encrypting a new backup."
)


def validate_recovery_password(password: str) -> str:
    if not isinstance(password, str) or not password or not password.strip():
        raise AegisError("Recovery password cannot be empty.")
    return password


def derive_key_from_password(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(password.encode("utf-8"))


def wrap_machine_key(machine: str, machine_key: bytes, recovery_password: str) -> Dict[str, Any]:
    salt = os.urandom(16)
    key = derive_key_from_password(validate_recovery_password(recovery_password), salt)
    nonce = os.urandom(12)
    cipher = AESGCM(key)
    ciphertext = cipher.encrypt(nonce, machine_key, None)
    return {
        "version": 1,
        "machine_id": machine,
        "created_at": now_rfc3339(),
        "salt_b64": base64.b64encode(salt).decode("ascii"),
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
    }


def unwrap_machine_key(envelope: Dict[str, Any], recovery_password: str) -> bytes:
    salt = base64.b64decode(envelope["salt_b64"])
    nonce = base64.b64decode(envelope["nonce_b64"])
    ciphertext = base64.b64decode(envelope["ciphertext_b64"])
    key = derive_key_from_password(validate_recovery_password(recovery_password), salt)
    cipher = AESGCM(key)
    return cipher.decrypt(nonce, ciphertext, None)


def materialize_settings(settings: Settings, recovery_password: Optional[str] = None) -> bool:
    ensure_repo_path_ready(settings.repo_path)
    repo = Path(settings.repo_path)

    (repo_machine_dir(repo, settings.machine_id) / "snapshots").mkdir(parents=True, exist_ok=True)
    (repo / "objects" / settings.machine_id).mkdir(parents=True, exist_ok=True)
    VAR_DIR.mkdir(parents=True, exist_ok=True)

    if not settings.encryption_enabled:
        return False

    envelope_path = key_envelope_path(repo, settings.machine_id)
    legacy_key = local_key_path(settings.machine_id)
    cred_path = local_key_credential_path(settings.machine_id)

    if legacy_key.exists():
        machine_key_value = legacy_key.read_bytes()
        if len(machine_key_value) != 32:
            raise AegisError("Legacy local key file is corrupt.")
        write_machine_key_credential(settings.machine_id, machine_key_value)
        legacy_key.unlink(missing_ok=True)

    elif not cred_path.exists():
        if envelope_path.exists():
            raise AegisError(
                "The local unlock credential is missing for this machine. "
                "Restore it with the recovery password instead of recreating encryption."
            )
        write_machine_key_credential(settings.machine_id, os.urandom(32))

    if envelope_path.exists():
        return False

    if not recovery_password:
        raise AegisError(RECOVERY_PASSWORD_REQUIRED_ERROR)

    machine_key_value = read_local_machine_key(settings.machine_id)
    envelope = wrap_machine_key(settings.machine_id, machine_key_value, recovery_password)
    save_json(envelope_path, envelope, mode=0o600)

    state = load_state()
    state.recovery_key_path = ""
    save_state(state)
    return True


def object_encode(plaintext: bytes, key: Optional[bytes]) -> bytes:
    if key is None:
        header = {
            "version": 1,
            "encrypted": False,
            "plain_len": len(plaintext),
            "nonce_b64": "",
        }
        header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
        return OBJECT_MAGIC + len(header_bytes).to_bytes(4, "big") + header_bytes + plaintext
    nonce = os.urandom(12)
    cipher = AESGCM(key)
    ciphertext = cipher.encrypt(nonce, plaintext, None)
    header = {
        "version": 1,
        "encrypted": True,
        "plain_len": len(plaintext),
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
    }
    header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
    return OBJECT_MAGIC + len(header_bytes).to_bytes(4, "big") + header_bytes + ciphertext


def object_decode(payload: bytes, key: Optional[bytes]) -> bytes:
    if not payload.startswith(OBJECT_MAGIC):
        raise AegisError("Invalid object format.")
    header_len = int.from_bytes(payload[len(OBJECT_MAGIC):len(OBJECT_MAGIC)+4], "big")
    offset = len(OBJECT_MAGIC) + 4
    header = json.loads(payload[offset:offset+header_len].decode("utf-8"))
    body = payload[offset+header_len:]
    if not header.get("encrypted"):
        return body
    if key is None:
        raise AegisError("This snapshot is encrypted and requires a key.")
    nonce = base64.b64decode(header["nonce_b64"])
    cipher = AESGCM(key)
    return cipher.decrypt(nonce, body, None)


class RepoWriter:
    def __init__(self, repo: Path, machine: str, chunk_size: int, key: Optional[bytes], io_yield_ms: int) -> None:
        self.repo = repo
        self.machine = machine
        self.chunk_size = chunk_size
        self.key = key
        self.io_yield_ms = max(0, io_yield_ms)
        self.buffer = bytearray()
        self.refs: List[ChunkRef] = []
        self.total_plaintext = 0
        self.hasher = hashlib.sha256()

    def write(self, data: bytes) -> None:
        self.buffer.extend(data)
        while len(self.buffer) >= self.chunk_size:
            piece = bytes(self.buffer[:self.chunk_size])
            del self.buffer[:self.chunk_size]
            self._store_chunk(piece)

    def finish(self) -> Tuple[List[ChunkRef], int, str]:
        if self.buffer:
            self._store_chunk(bytes(self.buffer))
            self.buffer.clear()
        return self.refs, self.total_plaintext, self.hasher.hexdigest()

    def _store_chunk(self, plaintext: bytes) -> None:
        self.hasher.update(plaintext)
        self.total_plaintext += len(plaintext)
        digest = sha256_hex(plaintext)
        obj = object_path(self.repo, self.machine, digest)
        if not obj.exists():
            obj.parent.mkdir(parents=True, exist_ok=True)
            encoded = object_encode(plaintext, self.key)
            atomic_write(obj, encoded, mode=0o600)
        self.refs.append(ChunkRef(hash=digest, plain_len=len(plaintext)))
        if self.io_yield_ms:
            time.sleep(self.io_yield_ms / 1000.0)


def kind_label(kind: str) -> str:
    return BACKUP_PROFILE_LABELS.get(kind, kind or BACKUP_PROFILE_LABELS["both"])


def build_include_paths(settings: Settings, kind: str) -> List[str]:
    if kind == "full_recovery":
        return ["."]
    includes = []
    for item in settings.portable_includes:
        cleaned = item.strip().lstrip("/")
        if cleaned and Path("/") .joinpath(cleaned).exists():
            includes.append(cleaned)
    return dedupe(includes)


def build_exclude_paths(settings: Settings, kind: str) -> List[str]:
    repo_rel = repo_relative_pattern(settings.repo_path)
    if kind == "full_recovery":
        base = list(settings.full_excludes)
        if repo_rel:
            base.extend([repo_rel, f"{repo_rel}/*"])
        return dedupe(base)
    base = list(settings.portable_excludes)
    if repo_rel:
        base.extend([repo_rel, f"{repo_rel}/*"])
    return dedupe(base)


def collect_snapshot_metadata(kind: str) -> SnapshotMetadata:
    partition_text = ""
    if shutil.which("sfdisk"):
        partition_text = run_command_optional(["sfdisk", "-d"])
    if not partition_text:
        partition_text = run_command_optional(["lsblk", "-f", "-o", "NAME,FSTYPE,SIZE,FSAVAIL,FSUSE%,MOUNTPOINTS,UUID"])
    flatpak_packages: List[str] = []
    snap_packages: List[str] = []
    if shutil.which("flatpak"):
        flatpak_output = run_command_optional(["flatpak", "list", "--app", "--columns=application"])
        flatpak_packages = [line.strip() for line in flatpak_output.splitlines() if line.strip()]
    if shutil.which("snap"):
        snap_output = run_command_optional(["snap", "list"])
        snap_packages = [line.split()[0] for line in snap_output.splitlines()[1:] if line.strip()]
    sources_chunks = []
    for candidate in [Path("/etc/apt/sources.list")] + sorted(Path("/etc/apt/sources.list.d").glob("*")) if Path("/etc/apt/sources.list.d").exists() else [Path("/etc/apt/sources.list")]:
        if candidate.exists() and candidate.is_file():
            try:
                sources_chunks.append(f"### {candidate}\n{candidate.read_text(encoding='utf-8', errors='ignore')}")
            except Exception:
                pass
    users = []
    try:
        for entry in pwd.getpwall():
            if entry.pw_uid >= 1000 and entry.pw_shell not in ("/usr/sbin/nologin", "/bin/false"):
                users.append(f"{entry.pw_name}:{entry.pw_uid}:{entry.pw_gid}:{entry.pw_dir}:{entry.pw_shell}")
    except Exception:
        pass
    notes = []
    if kind == "full_recovery":
        notes.append("Full Recovery restore should target an offline-mounted root filesystem.")
        notes.append("Mount target boot/efi before restore if the system uses EFI.")
    else:
        notes.append("Portable System State is intended for migration to different hardware.")
        notes.append("Hardware-bound kernel modules and host identity files are excluded by default.")
    manual_packages = [line.strip() for line in run_command_optional(["apt-mark", "showmanual"]).splitlines() if line.strip()]
    root_source_value = run_command_optional(["findmnt", "-nro", "SOURCE", "/"])
    boot_source_value = run_command_optional(["findmnt", "-nro", "SOURCE", "/boot"])
    efi_source_value = run_command_optional(["findmnt", "-nro", "SOURCE", "/boot/efi"])
    block_devices_json = run_command_optional([
        "lsblk", "-J", "-b",
        "-o", "NAME,PATH,TYPE,SIZE,RM,RO,TRAN,MODEL,SERIAL,FSTYPE,LABEL,UUID,PARTUUID,PKNAME,MOUNTPOINTS"
    ])
    return SnapshotMetadata(
        os_release=safe_read_text("/etc/os-release"),
        kernel_release=run_command_optional(["uname", "-r"]),
        root_fs=run_command_optional(["findmnt", "-nro", "FSTYPE", "/"]),
        dpkg_query=run_command_optional(["dpkg-query", "-W", "-f=${Package}\t${Version}\n"]),
        manual_packages=manual_packages,
        portable_manual_packages=filter_portable_manual_packages(manual_packages),
        flatpak_packages=flatpak_packages,
        snap_packages=snap_packages,
        apt_sources="\n".join(sources_chunks),
        users=users,
        fstab=safe_read_text("/etc/fstab"),
        hostname_file=safe_read_text("/etc/hostname"),
        hosts_file=safe_read_text("/etc/hosts"),
        machine_id_file=safe_read_text("/etc/machine-id"),
        mount_table=run_command_optional(["findmnt", "-A"]),
        partition_table=partition_text,
        block_devices_json=block_devices_json,
        root_source=root_source_value,
        boot_source=boot_source_value,
        efi_source=efi_source_value,
        firmware_mode=firmware_mode(),
        notes=notes,
    )


def build_tar_backup_command(includes: List[str], excludes: List[str]) -> List[str]:
    cmd = ["tar", "--xattrs", "--acls", "--numeric-owner", "--sparse", "--warning=no-file-changed", "--ignore-failed-read", "-cpf", "-", "-C", "/"]
    for ex in excludes:
        cmd.append(f"--exclude={ex}")
    cmd.extend(includes or ["."])
    return cmd


def write_manifest(settings: Settings, manifest: SnapshotManifest) -> None:
    path = manifest_path(Path(settings.repo_path), manifest.machine_id, manifest.id)
    payload = asdict(manifest)
    save_json(path, payload, mode=0o600)


def find_snapshot_manifest(repo: Path, snapshot_id: str) -> SnapshotManifest:
    machines_root = repo / "machines"
    if not machines_root.exists():
        raise AegisError(f"Snapshot not found: {snapshot_id}")
    for machine_dir in sorted(machines_root.iterdir()):
        candidate = machine_dir / "snapshots" / f"{snapshot_id}.json"
        if candidate.exists():
            data = load_json(candidate)
            return snapshot_from_dict(data)
    raise AegisError(f"Snapshot not found: {snapshot_id}")

def find_snapshot_manifest_with_path(repo: Path, snapshot_id: str) -> Tuple[SnapshotManifest, Path]:
    machines_root = repo / "machines"
    if not machines_root.exists():
        raise AegisError(f"Snapshot not found: {snapshot_id}")
    for machine_dir in sorted(machines_root.iterdir()):
        candidate = machine_dir / "snapshots" / f"{snapshot_id}.json"
        if candidate.exists():
            data = load_json(candidate)
            return snapshot_from_dict(data), candidate
    raise AegisError(f"Snapshot not found: {snapshot_id}")


def prune_empty_dirs(path: Path, stop_at: Path) -> None:
    current = path
    while current != stop_at:
        try:
            current.rmdir()
        except OSError:
            break
        current = current.parent


def delete_snapshot_from_repo(settings: Settings, snapshot_id: str) -> Tuple[SnapshotManifest, int]:
    repo = Path(settings.repo_path)
    with file_lock(LOCK_PATH):
        manifest, manifest_file = find_snapshot_manifest_with_path(repo, snapshot_id)
        candidate_hashes = {ref.hash for ref in manifest.archive_refs}

        manifest_file.unlink(missing_ok=True)

        remaining_hashes: Set[str] = set()
        snapshots_dir = repo_machine_dir(repo, manifest.machine_id) / "snapshots"
        if snapshots_dir.exists():
            for path in snapshots_dir.glob("*.json"):
                try:
                    other = snapshot_from_dict(load_json(path))
                    remaining_hashes.update(ref.hash for ref in other.archive_refs)
                except Exception:
                    continue

        removed_objects = 0
        machine_objects_root = repo / "objects" / manifest.machine_id
        for hash_hex in sorted(candidate_hashes - remaining_hashes):
            obj = object_path(repo, manifest.machine_id, hash_hex)
            if obj.exists():
                obj.unlink()
                removed_objects += 1
                prune_empty_dirs(obj.parent, machine_objects_root)

        return manifest, removed_objects

def snapshot_from_dict(data: Dict[str, Any]) -> SnapshotManifest:
    return SnapshotManifest(
        version=int(data["version"]),
        id=str(data["id"]),
        run_id=str(data["run_id"]),
        machine_id=str(data["machine_id"]),
        machine_label=str(data["machine_label"]),
        hostname=str(data["hostname"]),
        created_at=str(data["created_at"]),
        kind=str(data["kind"]),
        source_paths=list(data.get("source_paths") or []),
        exclude_paths=list(data.get("exclude_paths") or []),
        chunk_size=int(data.get("chunk_size", DEFAULT_CHUNK_MIB * 1024 * 1024)),
        archive_refs=[ChunkRef(hash=ref["hash"], plain_len=int(ref["plain_len"])) for ref in data.get("archive_refs") or []],
        archive_plaintext_bytes=int(data.get("archive_plaintext_bytes", 0)),
        archive_sha256=str(data.get("archive_sha256", "")),
        metadata=SnapshotMetadata(**(data.get("metadata") or {})),
        notes=list(data.get("notes") or []),
    )


def list_snapshots(settings: Settings) -> List[Dict[str, Any]]:
    repo = Path(settings.repo_path)
    out: List[Dict[str, Any]] = []
    machines_root = repo / "machines"
    if not machines_root.exists():
        return out
    for machine_dir in machines_root.iterdir():
        snapshots_dir = machine_dir / "snapshots"
        if not snapshots_dir.exists():
            continue
        for path in snapshots_dir.glob("*.json"):
            try:
                manifest = snapshot_from_dict(load_json(path))
                out.append({
                    "id": manifest.id,
                    "machine_id": manifest.machine_id,
                    "machine_label": manifest.machine_label,
                    "kind": manifest.kind,
                    "created_at": manifest.created_at,
                    "archive_bytes": manifest.archive_plaintext_bytes,
                })
            except Exception:
                continue
    out.sort(key=lambda x: x["created_at"], reverse=True)
    return out


def read_local_machine_key(machine: str) -> bytes:
    legacy = local_key_path(machine)
    if legacy.exists():
        data = legacy.read_bytes()
        if len(data) != 32:
            raise AegisError(f"Legacy local machine key is invalid for {machine}.")
        write_machine_key_credential(machine, data)
        legacy.unlink(missing_ok=True)
        return data

    return read_machine_key_credential(machine)


def load_key_envelope(repo: Path, machine: str) -> Dict[str, Any]:
    path = key_envelope_path(repo, machine)
    if not path.exists():
        raise AegisError(f"Key envelope is missing for {machine}.")
    return load_json(path)


def resolve_machine_key_for_manifest(settings: Settings, manifest: SnapshotManifest, recovery_password: Optional[str]) -> Optional[bytes]:
    repo = Path(settings.repo_path)
    objects_root = repo / "objects" / manifest.machine_id
    if not objects_root.exists():
        return None
    if has_local_machine_key(manifest.machine_id):
        return read_local_machine_key(manifest.machine_id)
    if recovery_password:
        envelope = load_key_envelope(repo, manifest.machine_id)
        return unwrap_machine_key(envelope, recovery_password)
    raise AegisError(
        f"No local key found for machine {manifest.machine_id}. Supply that machine's recovery password."
    )


def stream_archive_from_repo(repo: Path, manifest: SnapshotManifest, key: Optional[bytes], writer) -> str:
    hasher = hashlib.sha256()
    for ref in manifest.archive_refs:
        obj_path = object_path(repo, manifest.machine_id, ref.hash)
        if not obj_path.exists():
            raise AegisError(f"Missing object chunk: {obj_path}")
        payload = obj_path.read_bytes()
        plain = object_decode(payload, key)
        if len(plain) != ref.plain_len:
            raise AegisError(f"Chunk length mismatch for {ref.hash}")
        writer.write(plain)
        hasher.update(plain)
    return hasher.hexdigest()


@contextmanager
def file_lock(path: Path):
    import fcntl

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as fh:
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise AegisError("Another backup operation is already running.") from exc
        try:
            yield fh
        finally:
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)


def perform_backup(settings: Settings, profile: str) -> List[str]:
    start_stamp = now_rfc3339()
    state = load_state()
    state.last_run_at = start_stamp
    state.last_error = ""
    save_state(state)

    materialize_settings(settings)
    created: List[str] = []
    chunk_size = max(1, int(settings.chunk_size_mib)) * 1024 * 1024
    machine_key_value = read_local_machine_key(settings.machine_id) if settings.encryption_enabled else None
    with file_lock(LOCK_PATH):
        run_id = f"{utc_tag()}-{random_suffix(3)}"
        kinds = ["full_recovery", "portable_state"] if profile == "both" else [profile]
        for kind in kinds:
            update_stage(f"Collecting metadata for {kind_label(kind)}")
            metadata = collect_snapshot_metadata(kind)
            includes = build_include_paths(settings, kind)
            excludes = build_exclude_paths(settings, kind)
            update_stage(f"Capturing {kind_label(kind)}")
            writer = RepoWriter(Path(settings.repo_path), settings.machine_id, chunk_size, machine_key_value, settings.io_yield_ms)
            cmd = build_tar_backup_command(includes, excludes)
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            assert proc.stdout is not None
            while True:
                chunk = proc.stdout.read(BUFFER_SIZE)
                if not chunk:
                    break
                writer.write(chunk)
            stderr_data = proc.stderr.read().decode("utf-8", errors="ignore") if proc.stderr else ""
            returncode = proc.wait()
            if returncode != 0:
                raise AegisError(f"tar backup failed for {kind_label(kind)}: {stderr_data.strip() or returncode}")
            refs, total_bytes, archive_sha = writer.finish()
            manifest = SnapshotManifest(
                version=1,
                id=f"{utc_tag()}-{short_machine(settings.machine_id)}-{'full' if kind == 'full_recovery' else 'portable'}",
                run_id=run_id,
                machine_id=settings.machine_id,
                machine_label=settings.machine_label,
                hostname=hostname(),
                created_at=now_rfc3339(),
                kind=kind,
                source_paths=includes,
                exclude_paths=excludes,
                chunk_size=chunk_size,
                archive_refs=refs,
                archive_plaintext_bytes=total_bytes,
                archive_sha256=archive_sha,
                metadata=metadata,
                notes=list(metadata.notes),
            )
            write_manifest(settings, manifest)
            created.append(manifest.id)
        state = load_state()
        state.last_run_at = start_stamp
        state.last_success_at = now_rfc3339()
        state.last_error = ""
        save_state(state)
    if settings.peers_enabled and settings.peers:
        update_stage("Syncing peers")
        sync_peers(settings)
    return created


def build_tar_restore_command(target: Path, member: Optional[str]) -> subprocess.Popen:
    cmd = ["tar", "--xattrs", "--acls", "--numeric-owner", "-xpf", "-", "-C", str(target)]
    if member:
        cmd.append(normalize_member_path(member))
    return subprocess.Popen(cmd, stdin=subprocess.PIPE, stderr=subprocess.PIPE)


def restore_snapshot_from_repo(settings: Settings, snapshot_id: str, target: Path, member: Optional[str], apply_packages: bool, recovery_password: Optional[str]) -> None:
    manifest = find_snapshot_manifest(Path(settings.repo_path), snapshot_id)
    if manifest.kind == "full_recovery" and target.resolve() == Path("/"):
        raise AegisError("Full Recovery restore must target an offline-mounted root, not /.")
    key = resolve_machine_key_for_manifest(settings, manifest, recovery_password)
    extract_manifest_from_repo_to_target(Path(settings.repo_path), manifest, key, target, member)
    after_restore_actions(target, manifest, apply_packages)


def after_restore_actions(target: Path, manifest: SnapshotManifest, apply_packages: bool) -> None:
    if manifest.kind == "portable_state" and apply_packages:
        apply_portable_post_restore(target, manifest.metadata)
    if manifest.kind == "full_recovery" and target.resolve() != Path("/"):
        best_effort_full_restore_post_actions(target)


def apply_portable_post_restore(target: Path, metadata: SnapshotMetadata) -> None:
    if target.resolve() != Path("/"):
        return
    package_list = metadata.portable_manual_packages or filter_portable_manual_packages(metadata.manual_packages)
    if package_list:
        run_command(["apt-get", "update"], check=False, capture=True)
        chunk_size = 64
        for i in range(0, len(package_list), chunk_size):
            group = package_list[i:i+chunk_size]
            run_command(["apt-get", "install", "-y", *group], check=False, capture=True)
    if metadata.flatpak_packages and shutil.which("flatpak"):
        for app in metadata.flatpak_packages:
            run_command(["flatpak", "install", "-y", "flathub", app], check=False, capture=True)
    if metadata.snap_packages and shutil.which("snap"):
        for app in metadata.snap_packages:
            if app == "core":
                continue
            run_command(["snap", "install", app], check=False, capture=True)


@contextmanager
def mounted_chroot_bindings(target: Path):
    mounts: List[Tuple[str, Path]] = []
    try:
        (target / "proc").mkdir(parents=True, exist_ok=True)
        (target / "sys").mkdir(parents=True, exist_ok=True)
        (target / "dev").mkdir(parents=True, exist_ok=True)
        (target / "run").mkdir(parents=True, exist_ok=True)

        run_command(["mount", "-t", "proc", "proc", str(target / "proc")], check=True, capture=True)
        mounts.append(("plain", target / "proc"))

        for source, dest in [
            ("/sys", target / "sys"),
            ("/dev", target / "dev"),
            ("/run", target / "run"),
        ]:
            run_command(["mount", "--rbind", source, str(dest)], check=True, capture=True)
            subprocess.run(["mount", "--make-rslave", str(dest)], check=False, capture_output=True)
            mounts.append(("rbind", dest))

        yield
    finally:
        for kind, mount_path in reversed(mounts):
            if kind == "rbind":
                subprocess.run(["umount", "-R", "-lf", str(mount_path)], check=False, capture_output=True)
            else:
                subprocess.run(["umount", "-lf", str(mount_path)], check=False, capture_output=True)


def run_chroot(target: Path, args: List[str]) -> subprocess.CompletedProcess:
    clean_env = [
        "HOME=/root",
        "TERM=xterm",
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG=C",
        "LC_ALL=C",
    ]
    return subprocess.run(
        ["chroot", str(target), "/usr/bin/env", "-i", *clean_env, *args],
        check=False,
        capture_output=True,
        text=True,
    )


def run_chroot_checked(target: Path, args: List[str], label: Optional[str] = None) -> subprocess.CompletedProcess:
    result = run_chroot(target, args)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or str(result.returncode)
        raise AegisError(f"{label or ' '.join(args)} failed: {detail}")
    return result


def best_effort_full_restore_post_actions(target: Path, target_disk: Optional[str] = None) -> None:
    with mounted_chroot_bindings(target):
        if (target / "usr/sbin/update-initramfs").exists():
            run_chroot(target, ["/usr/sbin/update-initramfs", "-u", "-k", "all"])
        if target_disk and (target / "usr/sbin/grub-install").exists():
            if (target / "boot/efi").exists():
                run_chroot(target, ["/usr/sbin/grub-install", "--target=x86_64-efi", "--efi-directory=/boot/efi", "--bootloader-id=AegisVault", "--recheck", "--no-nvram"])
            run_chroot(target, ["/usr/sbin/grub-install", target_disk])
        if (target / "usr/sbin/update-grub").exists():
            run_chroot(target, ["/usr/sbin/update-grub"])
        if (target / "usr/bin/bootctl").exists() and (target / "boot/efi").exists():
            run_chroot(target, ["/usr/bin/bootctl", "install"])


def extract_manifest_from_repo_to_target(repo: Path, manifest: SnapshotManifest, key: Optional[bytes], target: Path, member: Optional[str]) -> None:
    target.mkdir(parents=True, exist_ok=True)
    proc = build_tar_restore_command(target, member)
    assert proc.stdin is not None
    digest = stream_archive_from_repo(repo, manifest, key, proc.stdin)
    proc.stdin.close()
    stderr_data = proc.stderr.read().decode("utf-8", errors="ignore") if proc.stderr else ""
    returncode = proc.wait()
    if returncode != 0:
        raise AegisError(f"tar extraction failed: {stderr_data.strip() or returncode}")
    if digest != manifest.archive_sha256:
        raise AegisError("Archive integrity mismatch during restore.")


def extract_archive_file_to_target(archive_file: Path, target: Path, member: Optional[str]) -> None:
    target.mkdir(parents=True, exist_ok=True)
    cmd = ["tar", "--xattrs", "--acls", "--numeric-owner", "-xpf", str(archive_file), "-C", str(target)]
    if member:
        cmd.append(normalize_member_path(member))
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise AegisError(f"tar extraction failed: {result.stderr.strip() or result.returncode}")


def write_guided_restore_fstab(target: Path, root_partition: str, efi_partition: str) -> None:
    root_uuid = blkid_value(root_partition, "UUID")
    efi_uuid = blkid_value(efi_partition, "UUID")
    fstab_path = target / "etc/fstab"
    if fstab_path.exists():
        shutil.copy2(fstab_path, target / "etc/fstab.aegisvault-original")
    content = textwrap.dedent(
        f"""
        # /etc/fstab generated by {APP_NAME} guided full restore
        UUID={root_uuid} / ext4 defaults,noatime 0 1
        UUID={efi_uuid} /boot/efi vfat umask=0077 0 1
        """
    ).strip() + "\n"
    atomic_write(fstab_path, content.encode("utf-8"), mode=0o644)

def wait_for_partition_device(path: str, timeout_seconds: int = 20) -> None:
    end = time.time() + timeout_seconds
    while time.time() < end:
        if Path(path).exists():
            return
        time.sleep(0.5)
    raise AegisError(f"Partition device did not appear: {path}")

def reread_partition_table(device: str) -> None:
    recover_block_device_state(device, allow_rescan=False)

def partition_is_mounted(device: str) -> bool:
    entry = find_block_device_entry(device)
    mountpoints = [mp for mp in ((entry or {}).get("mountpoints") or []) if mp]
    if mountpoints:
        return True
    return bool(run_command_optional(["findmnt", "-rn", "-S", device]).strip())


def ensure_device_tree_unmounted(device: str) -> None:
    disk = device_parent_disk(device) or device
    unmount_device_tree(disk)
    subprocess.run(["udevadm", "settle"], check=False, capture_output=True)


def prepare_partition_for_filesystem(device: str) -> None:
    ensure_device_tree_unmounted(device)

    subprocess.run(["wipefs", "-af", device], check=False, capture_output=True)

    parent_disk = device_parent_disk(device) or device
    parent_entry = find_block_device_entry(parent_disk) or {}
    is_usb_like = bool(parent_entry.get("removable")) or parent_entry.get("transport") == "usb"

    # Cheap USB flash media is much more likely to glitch on discard than to
    # benefit from it. Let mkfs overwrite the partition directly.
    if shutil.which("blkdiscard") and not is_usb_like:
        subprocess.run(["blkdiscard", "-f", device], check=False, capture_output=True)

    subprocess.run(["blockdev", "--flushbufs", device], check=False, capture_output=True)
    subprocess.run(["udevadm", "settle"], check=False, capture_output=True)
        
def wait_for_partition_ready(path: str, timeout_seconds: int = 45) -> None:
    disk = device_parent_disk(path) or path
    end = time.time() + timeout_seconds
    attempts = 0

    while time.time() < end:
        try:
            part_node = ensure_block_device_node(path, timeout_seconds=2)
        except AegisError:
            part_node = ""

        if part_node:
            entry = find_block_device_entry(part_node)
            size = int((entry or {}).get("size") or 0)

            if size <= 0:
                size = observed_block_device_size_bytes(part_node)

            if block_device_devtype(part_node) == "part" and not block_device_read_only(part_node) and size > 0:
                if partition_is_mounted(part_node):
                    ensure_device_tree_unmounted(disk)
                else:
                    return

        attempts += 1
        if attempts % 4 == 0:
            recover_block_device_state(disk, allow_rescan=True)
        else:
            reread_partition_table(disk)
        time.sleep(0.75)

    raise AegisError(f"Partition device did not become ready: {path}")

def mount_block_device_with_retry(device: str, mountpoint: Path, attempts: int = 3) -> None:
    disk = device_parent_disk(device) or device
    last_detail = "mount failed"

    for attempt in range(attempts):
        wait_for_partition_ready(device, timeout_seconds=45)
        result = subprocess.run(
            ["mount", device, str(mountpoint)],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            return

        last_detail = result.stderr.strip() or result.stdout.strip() or f"exit status {result.returncode}"
        recover_block_device_state(disk, allow_rescan=True)
        time.sleep(1.0 * (attempt + 1))

    raise AegisError(f"Could not mount {device}: {last_detail}")

def run_mkfs_with_retry(cmd: List[str], device: str, attempts: int = 4) -> None:
    disk = device_parent_disk(device) or device
    last_error: Optional[Exception] = None

    for attempt in range(attempts):
        ensure_device_tree_unmounted(disk)
        reread_partition_table(disk)
        wait_for_partition_ready(device, timeout_seconds=45)
        prepare_partition_for_filesystem(device)

        try:
            run_blockdev_command(cmd, device, check=True, capture=True)
            subprocess.run(["sync"], check=False, capture_output=True)
            subprocess.run(["blockdev", "--flushbufs", device], check=False, capture_output=True)
            subprocess.run(["udevadm", "settle"], check=False, capture_output=True)
            return
        except Exception as exc:
            last_error = exc
            detail = str(exc)

            if attempt == attempts - 1:
                if "Input/output error" in detail:
                    raise AegisError(
                        f"{detail} The selected USB drive is visible to Linux, "
                        f"but it did not complete a required write/flush on {device}. "
                        f"AegisVault only touched the selected target disk ({disk}). "
                        f"Try one different USB port; if the same error returns, "
                        f"replace the USB stick."
                    ) from exc
                raise

            time.sleep(1.5 * (attempt + 1))

    if last_error:
        raise last_error
        
def write_recovery_gpt_layout(device: str, expected_size: int = 0) -> None:
    target = ensure_block_device_node(device, timeout_seconds=10)

    for attempt in range(2):
        target = ensure_block_device_node(target, timeout_seconds=10)
        wait_for_expected_disk_size(target, expected_size, timeout_seconds=25)

        cmd = [
            "sgdisk",
            "--new=1:1M:+2M",
            "--typecode=1:ef02",
            "--change-name=1:bios_grub",
            "--new=2:0:+1024M",
            "--typecode=2:ef00",
            "--change-name=2:ESP",
            "--new=3:0:0",
            "--typecode=3:8300",
            "--change-name=3:root",
            target,
        ]

        result = run_blockdev_command(cmd, target, check=False, capture=True)

        parts: List[str] = []
        if result.stdout and result.stdout.strip():
            parts.append(result.stdout.strip())
        if result.stderr and result.stderr.strip():
            parts.append(result.stderr.strip())
        detail = "\n".join(parts).strip()

        if result.returncode == 0:
            return

        if result.returncode == 2 and "The operation has completed successfully." in detail:
            return

        if ("Disk is too small to hold GPT data" in detail or "Error is 6" in detail) and attempt == 0:
            subprocess.run(["udevadm", "settle"], check=False, capture_output=True)
            subprocess.run(["blockdev", "--rereadpt", target], check=False, capture_output=True)
            subprocess.run(["partprobe", target], check=False, capture_output=True)

            sysfs = Path("/sys/class/block") / Path(target).name
            udevadm = shutil.which("udevadm")
            if udevadm and sysfs.exists():
                subprocess.run(
                    [udevadm, "trigger", "--action=change", str(sysfs)],
                    check=False,
                    capture_output=True,
                )
                subprocess.run([udevadm, "settle"], check=False, capture_output=True)

            time.sleep(1.0)
            continue

        raise AegisError(f"{' '.join(cmd)} failed: {detail or f'exit status {result.returncode}'}")


def guided_partition_disk(device: str) -> Dict[str, str]:
    device = assert_safe_target_disk(device)
    identity = capture_block_device_identity(device)
    device = resolve_block_device_from_identity(identity, timeout_seconds=10)

    ensure_recovery_builder_prereqs()
    ensure_device_tree_unmounted(device)
    swapoff_device_tree(device)

    sgdisk_result = run_blockdev_command(
        ["sgdisk", "--zap-all", device],
        device,
        check=False,
        capture=True,
    )
    if sgdisk_result.returncode not in (0, 2, 3):
        detail = (
            sgdisk_result.stderr.strip()
            or sgdisk_result.stdout.strip()
            or f"exit status {sgdisk_result.returncode}"
        )
        raise AegisError(f"sgdisk --zap-all {device} failed: {detail}")

    subprocess.run(["udevadm", "settle"], check=False, capture_output=True)
    device = resolve_block_device_from_identity(identity, timeout_seconds=30)
    run_blockdev_command(["wipefs", "-af", device], device, check=False, capture=True)
    reread_partition_table(device)

    last_error: Optional[Exception] = None
    for attempt in range(3):
        device = resolve_block_device_from_identity(identity, timeout_seconds=30)
        ensure_device_tree_unmounted(device)
        reread_partition_table(device)

        try:
            write_recovery_gpt_layout(device, expected_size=int(identity.get("size") or 0))
            last_error = None
            break
        except Exception as exc:
            last_error = exc
            detail = str(exc)

            if (
                "Disk is too small to hold GPT data" in detail
                or "(34 sectors)" in detail
                or "invalid transient size" in detail
            ):
                if attempt < 2:
                    ensure_block_device_node(device, timeout_seconds=5)
                    sysfs = Path("/sys/class/block") / Path(device).name
                    if shutil.which("udevadm") and sysfs.exists():
                        subprocess.run(
                            ["udevadm", "trigger", "--action=change", "--settle", str(sysfs)],
                            check=False,
                            capture_output=True,
                        )
                    time.sleep(1.5 * (attempt + 1))
                    continue

                raise AegisError(
                    f"{device} is still reporting a bogus transient size to the kernel while partitioning. "
                    "AegisVault now avoids destructive delete/rescan behavior, but the current host block-device "
                    "state is already wedged. Reboot once, reconnect the USB stick, and retry."
                ) from exc

            if attempt == 2:
                if "unable to inform the kernel" in detail or "in use" in detail:
                    raise AegisError(
                        f"{detail} The selected USB disk would not accept a clean "
                        f"partition-table rescan. AegisVault only touched the selected "
                        f"target disk ({device}). Try unplugging and reconnecting it once."
                    ) from exc
                raise

            time.sleep(1.5 * (attempt + 1))

    if last_error is not None:
        raise last_error

    device = resolve_block_device_from_identity(identity, timeout_seconds=30)
    reread_partition_table(device)

    bios_partition = partition_path_for_number(device, 1, timeout_seconds=45)
    efi_partition = partition_path_for_number(device, 2, timeout_seconds=45)
    root_partition = partition_path_for_number(device, 3, timeout_seconds=45)

    ensure_device_tree_unmounted(device)
    wait_for_partition_ready(efi_partition, timeout_seconds=45)
    wait_for_partition_ready(root_partition, timeout_seconds=45)

    update_stage("Formatting recovery USB filesystems")

    run_mkfs_with_retry(
        ["mkfs.vfat", "-F", "32", "-n", "AEGIS-EFI", efi_partition],
        efi_partition,
        attempts=4,
    )
    run_mkfs_with_retry(
        ["mkfs.ext4", "-F", "-L", "AegisSystem", root_partition],
        root_partition,
        attempts=4,
    )

    device = resolve_block_device_from_identity(identity, timeout_seconds=30)
    reread_partition_table(device)

    return {
        "disk": device,
        "bios": bios_partition,
        "efi": efi_partition,
        "root": root_partition,
    }


def write_recovery_usb_mbr_layout(device: str, expected_size: int = 0) -> None:
    target = canonical_block_device_path(device) or device

    sfdisk_bin = shutil.which("sfdisk")
    if not sfdisk_bin:
        for candidate in (
            "/usr/sbin/sfdisk",
            "/sbin/sfdisk",
            "/usr/bin/sfdisk",
            "/bin/sfdisk",
        ):
            if Path(candidate).exists():
                sfdisk_bin = candidate
                break

    if not sfdisk_bin:
        raise AegisError(
            "sfdisk is required to create the recovery USB layout. "
            "Install the fdisk package."
        )

    layout_script = textwrap.dedent("""\
    label: dos
    unit: MiB

    1 : start=1, size=512, type=c, bootable
    2 : start=513, type=83
    """)

    last_detail = ""
    for attempt in range(3):
        wait_for_expected_disk_size(target, expected_size, timeout_seconds=25)
        ensure_device_tree_unmounted(target)

        result = subprocess.run(
            [sfdisk_bin, "--wipe", "always", target],
            input=layout_script,
            text=True,
            capture_output=True,
        )

        parts: List[str] = []
        if result.stdout and result.stdout.strip():
            parts.append(result.stdout.strip())
        if result.stderr and result.stderr.strip():
            parts.append(result.stderr.strip())
        detail = "\n".join(parts).strip()
        last_detail = detail or f"exit status {result.returncode}"

        if result.returncode == 0:
            reread_partition_table(target)
            return

        subprocess.run(["blockdev", "--rereadpt", target], check=False, capture_output=True)
        subprocess.run(["partprobe", target], check=False, capture_output=True)
        subprocess.run(["udevadm", "settle"], check=False, capture_output=True)
        time.sleep(1.5 * (attempt + 1))

    raise AegisError(f"{sfdisk_bin} recovery USB layout failed on {target}: {last_detail}")


def partition_recovery_usb_disk(device: str) -> Dict[str, str]:
    # Use the same robust GPT layout as guided full restore:
    #   1 = BIOS boot partition
    #   2 = EFI System Partition
    #   3 = ext4 root
    #
    # This avoids the flaky recovery-only MBR/sfdisk path and still matches
    # the later BIOS + UEFI grub-install steps in create_recovery_usb().
    return guided_partition_disk(device)


@contextmanager
def mounted_recovery_usb_target(device: str):
    layout = partition_recovery_usb_disk(device)
    mount_root = Path(tempfile.mkdtemp(prefix="aegisvault-recovery-usb-"))
    try:
        mount_block_device_with_retry(layout["root"], mount_root, attempts=3)
        (mount_root / "boot/efi").mkdir(parents=True, exist_ok=True)
        mount_block_device_with_retry(layout["efi"], mount_root / "boot/efi", attempts=3)
        yield layout, mount_root
    finally:
        subprocess.run(["umount", "-lf", str(mount_root / "boot/efi")], check=False, capture_output=True)
        subprocess.run(["umount", "-lf", str(mount_root)], check=False, capture_output=True)
        shutil.rmtree(mount_root, ignore_errors=True)

@contextmanager
def mounted_guided_target(device: str):
    layout = guided_partition_disk(device)
    mount_root = Path(tempfile.mkdtemp(prefix="aegisvault-target-"))
    try:
        mount_block_device_with_retry(layout["root"], mount_root, attempts=3)
        (mount_root / "boot/efi").mkdir(parents=True, exist_ok=True)
        mount_block_device_with_retry(layout["efi"], mount_root / "boot/efi", attempts=3)
        yield layout, mount_root
    finally:
        subprocess.run(["umount", "-lf", str(mount_root / "boot/efi")], check=False, capture_output=True)
        subprocess.run(["umount", "-lf", str(mount_root)], check=False, capture_output=True)
        shutil.rmtree(mount_root, ignore_errors=True)


def guided_full_restore_from_repo(settings: Settings, snapshot_id: str, target_disk: str, recovery_password: Optional[str]) -> None:
    manifest = find_snapshot_manifest(Path(settings.repo_path), snapshot_id)
    if manifest.kind != "full_recovery":
        raise AegisError("Guided full restore only works with Full Recovery snapshots.")
    key = resolve_machine_key_for_manifest(settings, manifest, recovery_password)
    with mounted_guided_target(target_disk) as (layout, mount_root):
        update_stage(f"Restoring {snapshot_id} to {target_disk}")
        extract_manifest_from_repo_to_target(Path(settings.repo_path), manifest, key, mount_root, None)
        write_guided_restore_fstab(mount_root, layout["root"], layout["efi"])
        best_effort_full_restore_post_actions(mount_root, layout["disk"])


def bundle_manifest_and_archive(bundle_path: Path, password: str) -> Tuple[SnapshotManifest, Path, tempfile.TemporaryDirectory]:
    if not password.strip():
        raise AegisError("Bundle password is required.")
    plain_bundle_path = secure_temp_path(".aegisvault-bundle-", ".tar")
    try:
        with bundle_path.open("rb") as src, plain_bundle_path.open("wb") as dst:
            decrypt_bundle_to_stream(src, password, dst)
        td = tempfile.TemporaryDirectory(dir=secure_temp_parent())
        temp_dir = Path(td.name)
        subprocess.run(["tar", "-xpf", str(plain_bundle_path), "-C", str(temp_dir)], check=True, capture_output=True)
        manifest = snapshot_from_dict(json.loads((temp_dir / "snapshot.json").read_text(encoding="utf-8")))
        return manifest, temp_dir / "archive.tar", td
    finally:
        plain_bundle_path.unlink(missing_ok=True)


def guided_full_restore_from_bundle(bundle_path: Path, password: str, target_disk: str) -> None:
    manifest, archive_path, td = bundle_manifest_and_archive(bundle_path, password)
    try:
        if manifest.kind != "full_recovery":
            raise AegisError("Guided full restore only works with Full Recovery bundles.")
        with mounted_guided_target(target_disk) as (layout, mount_root):
            update_stage(f"Restoring bundle to {target_disk}")
            extract_archive_file_to_target(archive_path, mount_root, None)
            write_guided_restore_fstab(mount_root, layout["root"], layout["efi"])
            best_effort_full_restore_post_actions(mount_root, layout["disk"])
    finally:
        td.cleanup()


def guided_full_restore_from_bundle_url(url: str, password: str, target_disk: str) -> None:
    temp = download_to_temp(url)
    try:
        guided_full_restore_from_bundle(temp, password, target_disk)
    finally:
        temp.unlink(missing_ok=True)


def create_recovery_usb(device: str) -> None:
    ensure_root()
    device = assert_safe_target_disk(device)

    entry = find_block_device_entry(device)
    size = int((entry or {}).get("size") or 0) or observed_block_device_size_bytes(device)
    if size and size < MIN_RECOVERY_USB_BYTES:
        raise AegisError("Recovery USB target is too small. Use at least 8 GB.")
    ensure_recovery_builder_prereqs()
    update_stage("Preparing recovery USB partitions")
    with mounted_recovery_usb_target(device) as (layout, mount_root):
        update_stage("Bootstrapping Debian recovery environment")
        run_command(["debootstrap", "--arch=amd64", DEFAULT_RECOVERY_SUITE, str(mount_root), DEFAULT_RECOVERY_MIRROR], check=True, capture=True)
        (mount_root / "etc/apt").mkdir(parents=True, exist_ok=True)
        atomic_write(
            mount_root / "etc/apt/sources.list",
            f"deb {DEFAULT_RECOVERY_MIRROR} {DEFAULT_RECOVERY_SUITE} main contrib non-free non-free-firmware\n".encode("utf-8"),
            mode=0o644,
        )
        if Path("/etc/resolv.conf").exists():
            shutil.copy2("/etc/resolv.conf", mount_root / "etc/resolv.conf")
        (mount_root / "var/lib/aegisvault/keys").mkdir(parents=True, exist_ok=True)
        try:
            probe = mount_root / ".aegisvault-write-test"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink()
        except OSError as exc:
            raise AegisError(f"Recovery USB target is not writable before package install: {exc}")
        with mounted_chroot_bindings(mount_root):
            update_stage("Installing recovery environment packages")
            run_chroot_checked(mount_root, ["/usr/bin/env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "update"], "apt-get update in recovery media")
            packages = [
                "linux-image-amd64",
                "systemd-sysv",
                "grub-common",
                "grub2-common",
                "grub-pc-bin",
                "grub-efi-amd64-bin",
                "python3",
                "python3-tk",
                "python3-cryptography",
                "xorg",
                "xinit",
                "openbox",
                "xterm",
                "dbus-x11",
                "network-manager",
                "ca-certificates",
                "curl",
                "rsync",
                "openssh-client",
                "tar",
                "parted",
                "dosfstools",
                "e2fsprogs",
                "btrfs-progs",
                "xfsprogs",
                "ntfs-3g",
                "exfatprogs",
                "util-linux",
                "sudo",
            ]
            try:
                run_chroot_checked(
                    mount_root,
                    [
                        "/usr/bin/env",
                        "DEBIAN_FRONTEND=noninteractive",
                        "apt-get",
                        "-o",
                        "Dpkg::Use-Pty=0",
                        "install",
                        "-y",
                        *packages,
                    ],
                    "package install in recovery media",
                )
            except AegisError as exc:
                detail = str(exc)
                if "Read-only file system" in detail:
                    raise AegisError(
                        "package install in recovery media failed because the target recovery USB "
                        "filesystem became read-only during installation. The locale and /dev/pts "
                        "warnings are not the real failure. Try the same job once with a different "
                        "USB port or a different USB stick."
                    ) from exc
                raise

            update_stage("Configuring recovery environment")
            (mount_root / "opt/aegisvault").mkdir(parents=True, exist_ok=True)
            shutil.copy2(Path(__file__), mount_root / "opt/aegisvault/aegisvault.py")
            wrapper = '#!/usr/bin/env bash\nexec python3 /opt/aegisvault/aegisvault.py "$@"\n'
            atomic_write(mount_root / "usr/local/bin/aegisvault", wrapper.encode("utf-8"), mode=0o755)

            service_text = textwrap.dedent("""
                [Unit]
                Description=AegisVault backup daemon
                After=network-online.target
                Wants=network-online.target

                [Service]
                Type=simple
                ExecStartPre=/bin/mkdir -p /run/aegisvault
                ExecStart=/usr/local/bin/aegisvault daemon
                Restart=on-failure
                RestartSec=5
                WorkingDirectory=/var/lib/aegisvault
                UMask=0077

                [Install]
                WantedBy=multi-user.target
            """).strip() + "\n"
            atomic_write(mount_root / "etc/systemd/system/aegisvault.service", service_text.encode("utf-8"), mode=0o644)

            override_dir = mount_root / "etc/systemd/system/getty@tty1.service.d"
            override_dir.mkdir(parents=True, exist_ok=True)
            getty_override = textwrap.dedent("""
                [Service]
                ExecStart=
                ExecStart=-/sbin/agetty --autologin root --noclear %I $TERM
            """).strip() + "\n"
            atomic_write(override_dir / "override.conf", getty_override.encode("utf-8"), mode=0o644)

            root_dir = mount_root / "root"
            root_dir.mkdir(parents=True, exist_ok=True)
            bash_profile = 'if [ -z "${DISPLAY:-}" ] && [ "$(tty)" = "/dev/tty1" ]; then\n  export AEGISVAULT_RECOVERY=1\n  startx\nfi\n'
            xinitrc = textwrap.dedent("""
                #!/usr/bin/env bash
                export AEGISVAULT_RECOVERY=1
                xsetroot -solid '#0e1116'
                /usr/bin/openbox-session &
                exec python3 /opt/aegisvault/aegisvault.py gui
            """).strip() + "\n"
            atomic_write(root_dir / ".bash_profile", bash_profile.encode("utf-8"), mode=0o644)
            atomic_write(root_dir / ".xinitrc", xinitrc.encode("utf-8"), mode=0o755)

            recovery_notice = textwrap.dedent("""
                AegisVault Recovery Media

                This environment boots directly into AegisVault so you can restore Full Recovery
                snapshots onto an internal disk. Use Guided Full Restore for the easiest path.
            """).strip() + "\n"
            atomic_write(mount_root / "etc/aegisvault-recovery", recovery_notice.encode("utf-8"), mode=0o644)
            atomic_write(mount_root / "etc/hostname", b"aegis-recovery\n", mode=0o644)
            atomic_write(mount_root / "etc/hosts", b"127.0.0.1 localhost\n127.0.1.1 aegis-recovery\n", mode=0o644)
            fstab_text = textwrap.dedent(f"""
                UUID={blkid_value(layout['root'], 'UUID')} / ext4 defaults,noatime 0 1
                UUID={blkid_value(layout['efi'], 'UUID')} /boot/efi vfat umask=0077 0 1
            """).strip() + "\n"
            atomic_write(mount_root / "etc/fstab", fstab_text.encode("utf-8"), mode=0o644)

            run_chroot_checked(mount_root, ["/bin/systemctl", "enable", "aegisvault.service"], "enable aegisvault.service")
            run_chroot_checked(mount_root, ["/bin/systemctl", "enable", "NetworkManager.service"], "enable NetworkManager.service")
            run_chroot_checked(mount_root, ["/usr/sbin/update-initramfs", "-u", "-k", "all"], "update-initramfs in recovery media")
            run_chroot_checked(mount_root, ["/usr/sbin/grub-install", "--target=i386-pc", layout["disk"]], "BIOS grub-install for recovery media")
            run_chroot_checked(mount_root, ["/usr/sbin/grub-install", "--target=x86_64-efi", "--efi-directory=/boot/efi", "--bootloader-id=AegisVaultRecovery", "--removable", "--recheck", "--no-nvram"], "UEFI grub-install for recovery media")
            run_chroot_checked(mount_root, ["/usr/sbin/update-grub"], "update-grub in recovery media")

    update_stage(f"Recovery USB is ready on {device}")


def encrypt_stream_to_bundle(source, dest, password: str) -> None:
    salt = os.urandom(16)
    header = {
        "version": 1,
        "created_at": now_rfc3339(),
        "salt_b64": base64.b64encode(salt).decode("ascii"),
    }
    header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
    dest.write(BUNDLE_MAGIC)
    dest.write(len(header_bytes).to_bytes(4, "big"))
    dest.write(header_bytes)
    key = derive_key_from_password(password, salt)
    cipher = AESGCM(key)
    while True:
        chunk = source.read(4 * 1024 * 1024)
        if not chunk:
            break
        nonce = os.urandom(12)
        ciphertext = cipher.encrypt(nonce, chunk, None)
        dest.write(len(ciphertext).to_bytes(4, "big"))
        dest.write(nonce)
        dest.write(ciphertext)
    dest.write((0).to_bytes(4, "big"))

def decrypt_bundle_to_stream(source, password: str, dest) -> None:
    magic = source.read(len(BUNDLE_MAGIC))
    if magic != BUNDLE_MAGIC:
        raise AegisError("Invalid bundle format.")
    header_len = int.from_bytes(source.read(4), "big")
    header = json.loads(source.read(header_len).decode("utf-8"))
    salt = base64.b64decode(header["salt_b64"])
    key = derive_key_from_password(password, salt)
    cipher = AESGCM(key)
    while True:
        size_bytes = source.read(4)
        if len(size_bytes) < 4:
            raise AegisError("Bundle is truncated.")
        cipher_len = int.from_bytes(size_bytes, "big")
        if cipher_len == 0:
            break
        nonce = source.read(12)
        ciphertext = source.read(cipher_len)
        if len(ciphertext) != cipher_len:
            raise AegisError("Bundle ciphertext is truncated.")
        plain = cipher.decrypt(nonce, ciphertext, None)
        dest.write(plain)


def export_bundle_from_repo(settings: Settings, snapshot_id: str, output: Path, password: str, recovery_password: Optional[str]) -> None:
    if not password.strip():
        raise AegisError("Bundle export requires a password.")
    manifest = find_snapshot_manifest(Path(settings.repo_path), snapshot_id)
    key = resolve_machine_key_for_manifest(settings, manifest, recovery_password)
    archive_tmp_path = secure_temp_path(".aegisvault-export-archive-", ".tar")
    with archive_tmp_path.open("wb") as archive_tmp:
        digest = stream_archive_from_repo(Path(settings.repo_path), manifest, key, archive_tmp)

    if digest != manifest.archive_sha256:
        archive_tmp_path.unlink(missing_ok=True)
        raise AegisError("Archive integrity mismatch while exporting bundle.")

    plain_bundle_path = secure_temp_path(".aegisvault-export-bundle-", ".tar")
    try:
        with tempfile.TemporaryDirectory() as td:
            temp_dir = Path(td)
            manifest_json = temp_dir / "snapshot.json"
            archive_copy = temp_dir / "archive.tar"
            manifest_json.write_text(json.dumps(asdict(manifest), indent=2), encoding="utf-8")
            shutil.copy2(archive_tmp_path, archive_copy)
            subprocess.run(["tar", "-cpf", str(plain_bundle_path), "-C", str(temp_dir), "snapshot.json", "archive.tar"], check=True, capture_output=True)
        output.parent.mkdir(parents=True, exist_ok=True)
        with plain_bundle_path.open("rb") as src, output.open("wb") as dst:
            encrypt_stream_to_bundle(src, dst, password)
    finally:
        archive_tmp_path.unlink(missing_ok=True)
        plain_bundle_path.unlink(missing_ok=True)


def restore_plain_archive_file(archive_file: Path, manifest: SnapshotManifest, target: Path, member: Optional[str], apply_packages: bool) -> None:
    if manifest.kind == "full_recovery" and target.resolve() == Path("/"):
        raise AegisError("Full Recovery restore must target an offline-mounted root, not /.")
    if manifest.archive_sha256 and sha256_file(archive_file) != manifest.archive_sha256:
        raise AegisError("Bundle archive integrity mismatch.")
    extract_archive_file_to_target(archive_file, target, member)
    after_restore_actions(target, manifest, apply_packages)


def restore_from_bundle_file(bundle_path: Path, password: str, target: Path, member: Optional[str], apply_packages: bool) -> None:
    manifest, archive_path, td = bundle_manifest_and_archive(bundle_path, password)
    try:
        restore_plain_archive_file(archive_path, manifest, target, member, apply_packages)
    finally:
        td.cleanup()


def download_to_temp(url: str) -> Path:
    req = urllib.request.Request(url, headers={"User-Agent": f"{APP_NAME}/1.0"})
    with urllib.request.urlopen(req) as response:
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            while True:
                chunk = response.read(4 * 1024 * 1024)
                if not chunk:
                    break
                fh.write(chunk)
            return Path(fh.name)


def restore_from_bundle_url(url: str, password: str, target: Path, member: Optional[str], apply_packages: bool) -> None:
    temp = download_to_temp(url)
    try:
        restore_from_bundle_file(temp, password, target, member, apply_packages)
    finally:
        temp.unlink(missing_ok=True)


def ssh_base_args(peer: PeerTarget) -> List[str]:
    args = ["ssh", "-p", str(peer.port)]
    if peer.identity_file:
        args.extend(["-i", peer.identity_file])
    return args


def rsync_ssh_command(peer: PeerTarget) -> str:
    base = f"ssh -p {peer.port}"
    if peer.identity_file:
        base += f" -i {peer.identity_file}"
    return base


def ensure_remote_repo(peer: PeerTarget) -> None:
    cmd = ssh_base_args(peer) + [peer.ssh_target, f"mkdir -p '{peer.repo_path}/objects' '{peer.repo_path}/machines'"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise AegisError(f"Failed to prepare peer {peer.label or peer.ssh_target}: {result.stderr.strip()}")


def rsync_local_to_remote(local_path: Path, peer: PeerTarget, remote_subdir: str) -> None:
    if not local_path.exists():
        return
    remote = f"{peer.ssh_target}:{peer.repo_path.rstrip('/')}/{remote_subdir.rstrip('/')}/"
    cmd = ["rsync", "-a", "-e", rsync_ssh_command(peer), f"{str(local_path).rstrip('/')}/", remote]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise AegisError(f"rsync push failed for {peer.label or peer.ssh_target}: {result.stderr.strip()}")


def rsync_remote_to_local(peer: PeerTarget, remote_subdir: str, local_path: Path) -> None:
    local_path.mkdir(parents=True, exist_ok=True)
    remote = f"{peer.ssh_target}:{peer.repo_path.rstrip('/')}/{remote_subdir.rstrip('/')}/"
    cmd = ["rsync", "-a", "-e", rsync_ssh_command(peer), remote, f"{str(local_path).rstrip('/')}/"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise AegisError(f"rsync pull failed for {peer.label or peer.ssh_target}: {result.stderr.strip()}")


def sync_peers(settings: Settings) -> None:
    if not settings.peers_enabled or not settings.peers:
        return
    repo = Path(settings.repo_path)
    local_objects = repo / "objects" / settings.machine_id
    local_meta = repo / "machines" / settings.machine_id
    for peer in settings.peers:
        if not peer.enabled or not peer.ssh_target.strip():
            continue
        update_stage(f"Syncing peer {peer.label or peer.ssh_target}")
        ensure_remote_repo(peer)
        rsync_local_to_remote(local_objects, peer, f"objects/{settings.machine_id}")
        rsync_local_to_remote(local_meta, peer, f"machines/{settings.machine_id}")
        rsync_remote_to_local(peer, "objects", repo / "objects")
        rsync_remote_to_local(peer, "machines", repo / "machines")
    state = load_state()
    state.last_sync_at = now_rfc3339()
    save_state(state)


def dashboard() -> Dashboard:
    settings = load_settings()
    state = load_state()
    warnings: List[str] = []
    if not Path(settings.repo_path).exists():
        warnings.append(f"Backup location is not available: {settings.repo_path}")
    if settings.notifications_enabled and not shutil.which("notify-send"):
        warnings.append("Desktop notifications are enabled, but notify-send is not installed. Install libnotify-bin to receive them.")
    if settings.encryption_enabled and local_key_path(settings.machine_id).exists():
        warnings.append(
            "A legacy plaintext local key still exists. Open settings once to migrate it into the system credential store."
        )
    elif settings.encryption_enabled and not has_local_machine_key(settings.machine_id):
        warnings.append("Encryption is enabled but the local unlock credential is missing.")
    if settings.peers_enabled and not settings.peers:
        warnings.append("Constellation mode is enabled but no peers are configured.")
    with RUNTIME.lock:
        current_job = dataclasses.replace(RUNTIME.current_job) if RUNTIME.current_job else None
        logs = list(RUNTIME.logs)
    return Dashboard(
        settings=settings,
        persistent=state,
        current_job=current_job,
        snapshots=list_snapshots(settings),
        warnings=warnings,
        logs=logs,
    )


def schedule_due(settings: Settings, state: PersistentState) -> bool:
    interval = settings.schedule.interval_minutes()
    if interval is None:
        return False
    if not state.last_run_at:
        return True
    try:
        last_epoch = int(time.mktime(time.strptime(state.last_run_at, "%Y-%m-%dT%H:%M:%SZ")))
    except Exception:
        return True
    return time.time() >= last_epoch + interval * 60


def run_job(name: str, func):
    with RUNTIME.lock:
        if RUNTIME.current_job is not None:
            raise AegisError("Another job is already running.")
        RUNTIME.current_job = JobState(name=name, stage="Queued", started_at=now_rfc3339())
    log_line(f"{name} queued")

    is_backup_job = "backup" in name.lower()
    try:
        settings = load_settings()
    except Exception:
        settings = Settings()

    notifications_enabled = bool(getattr(settings, "notifications_enabled", True))

    if is_backup_job and notifications_enabled:
        send_desktop_notification("Backup started", f"{name} has started.", urgency="normal")

    def worker():
        try:
            func()
            log_line(f"{name} finished successfully")
            if is_backup_job and notifications_enabled:
                send_desktop_notification("Backup finished", f"{name} completed successfully.", urgency="low")
        except Exception as exc:
            state = load_state()
            state.last_error = f"{exc}"
            save_state(state)
            log_line(f"{name} failed: {exc}")
            log_line(traceback.format_exc())
            if is_backup_job and notifications_enabled:
                send_desktop_notification("Backup needs attention", f"{name} failed: {exc}", urgency="critical")
        finally:
            with RUNTIME.lock:
                RUNTIME.current_job = None

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()

def handle_request(request: Dict[str, Any]) -> Dict[str, Any]:
    action = request.get("action")
    if action == "dashboard":
        return {"ok": True, "dashboard": asdict(dashboard())}
    if action == "save_settings":
        settings = settings_from_dict(request["settings"])
        recovery_password = request.get("recovery_password") or None
        created_new_envelope = materialize_settings(settings, recovery_password=recovery_password)
        save_settings(settings)
        install_or_update_host_service()

        state = load_state()
        state.recovery_key_path = ""
        save_state(state)

        if created_new_envelope:
            return {
                "ok": True,
                "message": "Settings saved. Password set for encrypted restore.",
            }
        return {"ok": True, "message": "Settings saved."}
    if action == "run_backup":
        profile = normalize_backup_profile(request.get("profile", "both"))
        run_job(f"Backup ({kind_label(profile)})", lambda: perform_backup(load_settings(), profile))
        return {"ok": True, "message": "Backup started."}
    if action == "run_export":
        snapshot_id = request["snapshot"]
        output = Path(request["output"])
        password = request["password"]
        recovery_password = request.get("recovery_password") or None
        run_job(
            f"Export bundle {snapshot_id}",
            lambda: export_bundle_from_repo(load_settings(), snapshot_id, output, password, recovery_password),
        )
        return {"ok": True, "message": "Bundle export started."}
    if action == "run_restore_repo":
        run_job(
            f"Restore snapshot {request['snapshot']}",
            lambda: restore_snapshot_from_repo(
                load_settings(),
                request["snapshot"],
                Path(request["target"]),
                request.get("member") or None,
                bool(request.get("apply_packages", False)),
                request.get("recovery_password") or None,
            ),
        )
        return {"ok": True, "message": "Restore started."}
    if action == "run_restore_bundle":
        bundle_path = request.get("bundle_path")
        bundle_url = request.get("bundle_url")
        password = request.get("password", "")
        target = Path(request["target"])
        member = request.get("member") or None
        apply_packages = bool(request.get("apply_packages", False))
        if bundle_path:
            run_job(
                f"Restore bundle {bundle_path}",
                lambda: restore_from_bundle_file(Path(bundle_path), password, target, member, apply_packages),
            )
        elif bundle_url:
            run_job(
                f"Restore bundle {bundle_url}",
                lambda: restore_from_bundle_url(bundle_url, password, target, member, apply_packages),
            )
        else:
            raise AegisError("Provide bundle_path or bundle_url.")
        return {"ok": True, "message": "Bundle restore started."}
    if action == "delete_snapshot":
        snapshot_id = str(request.get("snapshot") or "").strip()
        if not snapshot_id:
            raise AegisError("Choose a snapshot first.")
        with RUNTIME.lock:
            if RUNTIME.current_job is not None:
                raise AegisError("Wait for the current job to finish before deleting a snapshot.")
        manifest, removed_objects = delete_snapshot_from_repo(load_settings(), snapshot_id)
        return {
            "ok": True,
            "message": f"{kind_label(manifest.kind)} snapshot {snapshot_id} deleted. Removed {removed_objects} unreferenced data chunk(s).",
        }
    if action == "set_repo_path":
        repo_path = str(request.get("repo_path") or "").strip()
        if not repo_path:
            raise AegisError("Backup location is required.")
        ensure_repo_path_ready(repo_path)
        settings = load_settings()
        settings.repo_path = repo_path
        if not settings.full_excludes:
            settings.full_excludes = default_full_excludes(settings.repo_path)
        save_settings(settings)
        return {"ok": True, "message": f"Backup location set to {repo_path}."}
    if action == "mount_backup_device":
        device = str(request.get("device") or "").strip()
        if not device:
            raise AegisError("Choose a drive first.")
        mountpoint = mount_backup_browser_device(device)
        return {
            "ok": True,
            "mountpoint": mountpoint,
            "message": f"Mounted {device} at {mountpoint}.",
        }
    if action == "run_create_recovery_usb":
        device = str(request.get("device") or "").strip()
        if not device:
            raise AegisError("Choose a target USB disk first.")
        run_job(f"Create recovery USB on {device}", lambda: create_recovery_usb(device))
        return {"ok": True, "message": "Recovery USB creation started."}
    if action == "run_guided_restore_repo":
        device = str(request.get("target_disk") or "").strip()
        snapshot_id = str(request.get("snapshot") or "").strip()
        recovery_password = request.get("recovery_password") or None
        if not snapshot_id or not device:
            raise AegisError("Snapshot and target disk are required.")
        run_job(
            f"Guided restore {snapshot_id} to {device}",
            lambda: guided_full_restore_from_repo(load_settings(), snapshot_id, device, recovery_password),
        )
        return {"ok": True, "message": "Guided full restore started."}
    if action == "run_guided_restore_bundle":
        device = str(request.get("target_disk") or "").strip()
        bundle_path = str(request.get("bundle_path") or "").strip()
        bundle_url = str(request.get("bundle_url") or "").strip()
        password = str(request.get("password") or "")
        if not device:
            raise AegisError("Target disk is required.")
        if bundle_path:
            run_job(f"Guided restore bundle to {device}", lambda: guided_full_restore_from_bundle(Path(bundle_path), password, device))
        elif bundle_url:
            run_job(f"Guided restore URL bundle to {device}", lambda: guided_full_restore_from_bundle_url(bundle_url, password, device))
        else:
            raise AegisError("Provide a bundle file or URL.")
        return {"ok": True, "message": "Guided full restore started."}
    if action == "sync_peers":
        run_job("Peer sync", lambda: sync_peers(load_settings()))
        return {"ok": True, "message": "Peer sync started."}
    raise AegisError(f"Unknown action: {action}")


def scheduler_loop():
    while True:
        time.sleep(60)
        try:
            settings = load_settings()
            state = load_state()

            if not settings.onboarding_complete:
                continue
            if not schedule_due(settings, state):
                continue

            with RUNTIME.lock:
                if RUNTIME.current_job is not None:
                    continue

            profile = normalize_backup_profile(settings.default_backup_profile)
            run_job("Scheduled backup", lambda: perform_backup(load_settings(), profile))
        except Exception as exc:
            log_line(f"Scheduler error: {exc}")


def daemon_main() -> int:
    ensure_root()
    VAR_DIR.mkdir(parents=True, exist_ok=True)
    LEGACY_KEY_DIR.mkdir(parents=True, exist_ok=True)
    Path("/run/aegisvault").mkdir(parents=True, exist_ok=True)
    if os.path.exists(SOCKET_PATH):
        os.unlink(SOCKET_PATH)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(SOCKET_PATH)
    try:
        gid = grp.getgrnam("aegisvault").gr_gid
        os.chown(SOCKET_PATH, 0, gid)
    except Exception:
        pass
    os.chmod(SOCKET_PATH, 0o660)
    server.listen(32)
    log_line("Daemon started.")
    threading.Thread(target=scheduler_loop, daemon=True).start()

    while True:
        conn, _ = server.accept()
        threading.Thread(target=serve_connection, args=(conn,), daemon=True).start()


def serve_connection(conn: socket.socket) -> None:
    try:
        data = b""
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                break
            data += chunk
        if not data:
            return
        request = json.loads(data.decode("utf-8"))
        response = handle_request(request)
    except Exception as exc:
        response = {"ok": False, "error": str(exc)}
    try:
        conn.sendall(json.dumps(response).encode("utf-8"))
    finally:
        conn.close()


def send_daemon_request_raw(payload: Dict[str, Any]) -> Dict[str, Any]:
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.connect(SOCKET_PATH)
    client.sendall(json.dumps(payload).encode("utf-8"))
    client.shutdown(socket.SHUT_WR)
    data = b""
    while True:
        chunk = client.recv(65536)
        if not chunk:
            break
        data += chunk
    client.close()
    if not data:
        raise AegisError("Daemon returned no data.")
    return json.loads(data.decode("utf-8"))


def _pkexec_env_prefix() -> List[str]:
    forwarded = []
    for name in (
        "DISPLAY",
        "XAUTHORITY",
        "XDG_RUNTIME_DIR",
        "WAYLAND_DISPLAY",
        "DBUS_SESSION_BUS_ADDRESS",
        "XDG_CURRENT_DESKTOP",
        "DESKTOP_SESSION",
    ):
        value = os.environ.get(name)
        if value:
            forwarded.append(f"{name}={value}")
    return forwarded


def authorize_socket_access_for_user() -> None:
    global _SOCKET_AUTH_FAILED

    if os.geteuid() == 0:
        return
    if _SOCKET_AUTH_FAILED:
        raise AegisError("Administrator authentication was canceled or failed.")

    pkexec = shutil.which("pkexec")
    if not pkexec:
        raise AegisError("pkexec is required to authorize AegisVault for this desktop session.")

    user_name = pwd.getpwuid(os.getuid()).pw_name
    cmd = [
        pkexec,
        "env",
        *_pkexec_env_prefix(),
        sys.executable,
        str(Path(__file__).resolve()),
        "authorize-socket",
        "--user",
        user_name,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        _SOCKET_AUTH_FAILED = True
        detail = result.stderr.strip() or result.stdout.strip() or "Administrator authentication was canceled or failed."
        raise AegisError(detail)


def send_daemon_request(payload: Dict[str, Any]) -> Dict[str, Any]:
    try:
        return send_daemon_request_raw(payload)
    except PermissionError:
        authorize_socket_access_for_user()
        return send_daemon_request_raw(payload)
    except OSError as exc:
        if exc.errno in (errno.EACCES, errno.EPERM, errno.ENOENT, errno.ECONNREFUSED):
            authorize_socket_access_for_user()
            return send_daemon_request_raw(payload)
        raise

def authorize_socket_command(user: str) -> int:
    try:
        ensure_root()
        Path("/run/aegisvault").mkdir(parents=True, exist_ok=True)

        install_or_update_host_service()
        subprocess.run(["systemctl", "enable", "--now", "aegisvault.service"], check=False, capture_output=True)

        deadline = time.time() + 8
        while time.time() < deadline:
            if Path(SOCKET_PATH).exists():
                break
            time.sleep(0.2)

        if not Path(SOCKET_PATH).exists():
            raise AegisError("AegisVault daemon socket was not created.")

        if shutil.which("setfacl"):
            result = subprocess.run(
                ["setfacl", "-m", f"user:{user}:rw", SOCKET_PATH],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                os.chmod(SOCKET_PATH, 0o666)
        else:
            os.chmod(SOCKET_PATH, 0o666)

        os.chmod("/run/aegisvault", 0o755)
        print("Socket access granted.")
        return 0
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1


def init_command(repo: Optional[str], label: Optional[str], encryption: bool, recovery_password: Optional[str]) -> int:
    ensure_root()
    settings = load_settings()
    if repo:
        settings.repo_path = repo
        settings.full_excludes = default_full_excludes(settings.repo_path)
    if label:
        settings.machine_label = label
    settings.encryption_enabled = encryption
    settings.onboarding_complete = False
    if not settings.machine_id:
        settings.machine_id = machine_id()
    if not settings.machine_label:
        settings.machine_label = hostname()
    settings.portable_includes = settings.portable_includes or default_portable_includes()
    settings.portable_excludes = settings.portable_excludes or default_portable_excludes()

    try:
        materialize_settings(settings, recovery_password=recovery_password)
    except AegisError as exc:
        if str(exc) != RECOVERY_PASSWORD_REQUIRED_ERROR or not encryption:
            raise
        recovery_password = prompt_new_recovery_password_cli()
        materialize_settings(settings, recovery_password=recovery_password)

    save_settings(settings)
    install_or_update_host_service()

    print(f"{APP_NAME} initialized at {settings.repo_path}")
    if encryption:
        print("Encrypted backups are enabled.")
        print("Use your chosen recovery password to restore on another machine or after a reset.")
    return 0


def print_status_json() -> int:
    try:
        try:
            response = send_daemon_request({"action": "dashboard"})
            payload = response["dashboard"]
        except Exception:
            payload = asdict(dashboard())
        print(json.dumps(payload, indent=2))
        return 0
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1


def backup_now_command(profile: str, direct: bool) -> int:
    try:
        if not direct:
            try:
                response = send_daemon_request({"action": "run_backup", "profile": profile})
                if not response.get("ok"):
                    raise AegisError(response.get("error", "Unknown daemon error"))
                print(response["message"])
                return 0
            except Exception:
                pass
        ensure_root()
        ids = perform_backup(load_settings(), profile)
        print("Created snapshots:")
        for snapshot_id in ids:
            print(f"  {snapshot_id}")
        return 0
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1


def export_bundle_command(snapshot: str, output: str, password: str, recovery_password: Optional[str], direct: bool) -> int:
    try:
        if not direct:
            try:
                response = send_daemon_request({
                    "action": "run_export",
                    "snapshot": snapshot,
                    "output": output,
                    "password": password,
                    "recovery_password": recovery_password or "",
                })
                if not response.get("ok"):
                    raise AegisError(response.get("error", "Unknown daemon error"))
                print(response["message"])
                return 0
            except Exception:
                pass
        ensure_root()
        export_bundle_from_repo(load_settings(), snapshot, Path(output), password, recovery_password)
        print(f"Bundle written to {output}")
        return 0
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1


def restore_command(args) -> int:
    try:
        guided = bool(getattr(args, "guided", False))
        target_disk = getattr(args, "target_disk", "") or ""
        if not args.direct:
            try:
                if guided:
                    if args.snapshot:
                        payload = {
                            "action": "run_guided_restore_repo",
                            "snapshot": args.snapshot,
                            "target_disk": target_disk,
                            "recovery_password": args.recovery_password or "",
                        }
                    else:
                        payload = {
                            "action": "run_guided_restore_bundle",
                            "bundle_path": args.bundle or "",
                            "bundle_url": args.url or "",
                            "password": args.bundle_password or "",
                            "target_disk": target_disk,
                        }
                elif args.snapshot:
                    payload = {
                        "action": "run_restore_repo",
                        "snapshot": args.snapshot,
                        "target": args.target,
                        "member": args.path or "",
                        "apply_packages": bool(args.apply_packages),
                        "recovery_password": args.recovery_password or "",
                    }
                else:
                    payload = {
                        "action": "run_restore_bundle",
                        "bundle_path": args.bundle or "",
                        "bundle_url": args.url or "",
                        "password": args.bundle_password or "",
                        "target": args.target,
                        "member": args.path or "",
                        "apply_packages": bool(args.apply_packages),
                    }
                response = send_daemon_request(payload)
                if not response.get("ok"):
                    raise AegisError(response.get("error", "Unknown daemon error"))
                print(response["message"])
                return 0
            except Exception:
                pass

        ensure_root()
        settings = load_settings()
        if guided:
            if not target_disk:
                raise AegisError("Guided restore requires --target-disk /dev/sdX.")
            if args.snapshot:
                guided_full_restore_from_repo(settings, args.snapshot, target_disk, args.recovery_password)
            elif args.bundle:
                guided_full_restore_from_bundle(Path(args.bundle), args.bundle_password or "", target_disk)
            elif args.url:
                guided_full_restore_from_bundle_url(args.url, args.bundle_password or "", target_disk)
            else:
                raise AegisError("Provide --snapshot, --bundle, or --url.")
        else:
            target = Path(args.target)
            if args.snapshot:
                restore_snapshot_from_repo(settings, args.snapshot, target, args.path, bool(args.apply_packages), args.recovery_password)
            elif args.bundle:
                restore_from_bundle_file(Path(args.bundle), args.bundle_password or "", target, args.path, bool(args.apply_packages))
            elif args.url:
                restore_from_bundle_url(args.url, args.bundle_password or "", target, args.path, bool(args.apply_packages))
            else:
                raise AegisError("Provide --snapshot, --bundle, or --url.")
        print("Restore finished.")
        return 0
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1


def list_disks_command() -> int:
    try:
        disks = list_disk_choices()
        for disk in disks:
            print(f"{disk['path']}	{disk['display']}")
        return 0
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1


def create_recovery_usb_command(device: str, direct: bool) -> int:
    try:
        if not direct:
            try:
                response = send_daemon_request({"action": "run_create_recovery_usb", "device": device})
                if not response.get("ok"):
                    raise AegisError(response.get("error", "Unknown daemon error"))
                print(response["message"])
                return 0
            except Exception:
                pass
        ensure_root()
        create_recovery_usb(device)
        print(f"Recovery USB created on {device}")
        return 0
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1


def sync_peers_command(direct: bool) -> int:
    try:
        if not direct:
            try:
                response = send_daemon_request({"action": "sync_peers"})
                if not response.get("ok"):
                    raise AegisError(response.get("error", "Unknown daemon error"))
                print(response["message"])
                return 0
            except Exception:
                pass
        ensure_root()
        sync_peers(load_settings())
        print("Peer sync finished.")
        return 0
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1


# ---------------- GUI ----------------


def gui_main() -> int:
    import tkinter as tk
    from tkinter import filedialog, messagebox, simpledialog, ttk
    from tkinter.scrolledtext import ScrolledText

    class App:
        def __init__(self, root: tk.Tk) -> None:
            self.root = root
            self.root.title(APP_NAME)
            self.root.geometry("1220x820")
            self.root.minsize(1020, 700)
            self.configure_theme()

            self.message_var = tk.StringVar(value="")
            self.status_var = tk.StringVar(value="Loading…")

            self.machine_label_var = tk.StringVar()
            self.repo_path_var = tk.StringVar()
            self.encryption_var = tk.BooleanVar(value=True)
            self.notifications_enabled_var = tk.BooleanVar(value=True)
            self.default_backup_profile_var = tk.StringVar(value="both")
            self.storage_choice_var = tk.StringVar(value="")
            self.schedule_enabled_var = tk.BooleanVar(value=False)
            self.schedule_preset_var = tk.StringVar(value="manual")
            self.schedule_custom_var = tk.StringVar(value="60")
            self.io_yield_var = tk.StringVar(value="2")
            self.apply_packages_var = tk.BooleanVar(value=True)
            self.peers_enabled_var = tk.BooleanVar(value=False)

            self.export_password_var = tk.StringVar()
            self.export_recovery_key_var = tk.StringVar(value="")
            self.repo_restore_target_var = tk.StringVar(value="/")
            self.repo_restore_path_var = tk.StringVar(value="")
            self.repo_recovery_key_var = tk.StringVar(value="")
            self.bundle_restore_target_var = tk.StringVar(value="/")
            self.bundle_restore_path_var = tk.StringVar(value="")
            self.bundle_password_var = tk.StringVar(value="")
            self.bundle_file_var = tk.StringVar(value="")
            self.bundle_url_var = tk.StringVar(value="")
            self.repo_source_var = tk.StringVar(value="")
            self.repo_candidate_var = tk.StringVar(value="")
            self.recovery_usb_device_var = tk.StringVar(value="")
            self.guided_target_disk_var = tk.StringVar(value="")

            self.peer_label_var = tk.StringVar()
            self.peer_target_var = tk.StringVar()
            self.peer_repo_var = tk.StringVar(value=DEFAULT_REPO)
            self.peer_port_var = tk.StringVar(value="22")
            self.peer_identity_var = tk.StringVar(value="")
            self.selected_snapshot_id = ""
            self.dashboard_payload: Dict[str, Any] = {}
            self.settings_loaded = False
            self.recovery_mode = is_recovery_environment()
            self.ui_configured_state: Optional[bool] = None
            self.repo_candidates: List[str] = []
            self.usb_choice_map: Dict[str, str] = {}
            self.guided_disk_map: Dict[str, str] = {}
            self.recovery_mounts: List[str] = []

            self.storage_choices: List[str] = []
            self.storage_choice_map: Dict[str, str] = {}
            self.activity_bar_running = False

            outer = ttk.Frame(self.root, padding=16)
            outer.pack(fill="both", expand=True)

            header = ttk.Frame(outer)
            header.pack(fill="x", pady=(0, 12))

            ttk.Label(header, text=APP_NAME, style="Header.TLabel").pack(side="left")
            ttk.Label(header, textvariable=self.status_var, style="Muted.TLabel").pack(side="right")

            self.notebook = ttk.Notebook(outer)
            self.notebook.pack(fill="both", expand=True)

            self.setup_tab = ttk.Frame(self.notebook, padding=16)
            self.overview_tab = ttk.Frame(self.notebook, padding=16)
            self.backup_tab = ttk.Frame(self.notebook, padding=16)
            self.restore_tab = ttk.Frame(self.notebook, padding=16)
            self.constellation_tab = ttk.Frame(self.notebook, padding=16)
            self.settings_tab = ttk.Frame(self.notebook, padding=16)

            self.notebook.add(self.setup_tab, text="Setup")
            self.notebook.add(self.overview_tab, text="Overview")
            self.notebook.add(self.backup_tab, text="Backup")
            self.notebook.add(self.restore_tab, text="Restore")
            self.notebook.add(self.constellation_tab, text="Constellation")
            self.notebook.add(self.settings_tab, text="Settings")

            self.build_setup_tab()
            self.build_overview_tab()
            self.build_backup_tab()
            self.build_restore_tab()
            self.build_constellation_tab()
            self.build_settings_tab()
            self.apply_configuration_state(False)

            footer = ttk.Frame(outer)
            footer.pack(fill="x", pady=(12, 0))

            ttk.Label(
                footer,
                textvariable=self.message_var,
                wraplength=980,
            ).pack(side="left", fill="x", expand=True)

            self.activity_bar = ttk.Progressbar(footer, mode="indeterminate", length=180)
            self.activity_bar.pack(side="right")

            if self.recovery_mode and os.geteuid() == 0:
                try:
                    self.recovery_mounts = auto_mount_recovery_sources()
                except Exception:
                    self.recovery_mounts = []
            self.refresh_local_device_lists()
            self.scan_repository_candidates(auto_use=False)
            if self.recovery_mode:
                hint = "Recovery mode: use Guided Full Restore for the easiest same-machine disaster restore."
                if self.recovery_mounts:
                    hint += f" Mounted source volumes: {', '.join(self.recovery_mounts)}."
                self.message_var.set(hint)
            self.root.after(150, self.refresh_dashboard)
            self.root.after(2500, self.periodic_refresh)

        def configure_theme(self) -> None:
            self.root.configure(bg="#0e1116")

            self.root.option_add("*TCombobox*Listbox*Background", "#151b23")
            self.root.option_add("*TCombobox*Listbox*Foreground", "#e6edf3")
            self.root.option_add("*TCombobox*Listbox*selectBackground", "#1a2330")
            self.root.option_add("*TCombobox*Listbox*selectForeground", "#ffffff")
            self.root.option_add("*Listbox*Background", "#151b23")
            self.root.option_add("*Listbox*Foreground", "#e6edf3")
            self.root.option_add("*Listbox*selectBackground", "#1a2330")
            self.root.option_add("*Listbox*selectForeground", "#ffffff")

            style = ttk.Style()
            try:
                style.theme_use("clam")
            except Exception:
                pass

            style.configure(".", background="#0e1116", foreground="#e6edf3", fieldbackground="#151b23")
            style.configure("TFrame", background="#0e1116")
            style.configure("TLabel", background="#0e1116", foreground="#e6edf3")
            style.configure("Header.TLabel", background="#0e1116", foreground="#e6edf3", font=("TkDefaultFont", 11, "bold"))
            style.configure("Muted.TLabel", background="#0e1116", foreground="#9fb3c8")

            style.configure(
                "TButton",
                background="#165dcb",
                foreground="#ffffff",
                padding=(12, 8),
                relief="flat",
                borderwidth=0,
                focusthickness=0,
            )
            style.map(
                "TButton",
                background=[("pressed", "#114da7"), ("active", "#1a69df"), ("disabled", "#2b3138")],
                foreground=[("disabled", "#93a4b7")],
                relief=[("pressed", "flat"), ("active", "flat")],
            )

            style.configure("TCheckbutton", background="#0e1116", foreground="#e6edf3")
            style.configure("TRadiobutton", background="#0e1116", foreground="#e6edf3")
            style.configure("TEntry", fieldbackground="#151b23", foreground="#e6edf3", insertcolor="#e6edf3")

            style.configure(
                "TCombobox",
                fieldbackground="#151b23",
                background="#151b23",
                foreground="#e6edf3",
                arrowcolor="#9fb3c8",
                bordercolor="#243041",
                lightcolor="#151b23",
                darkcolor="#151b23",
                insertcolor="#e6edf3",
                selectbackground="#1a2330",
                selectforeground="#ffffff",
            )
            style.map(
                "TCombobox",
                fieldbackground=[("readonly", "#151b23"), ("!disabled", "#151b23")],
                background=[("readonly", "#151b23"), ("active", "#151b23")],
                foreground=[("readonly", "#e6edf3"), ("!disabled", "#e6edf3")],
                arrowcolor=[("active", "#ffffff"), ("!disabled", "#9fb3c8")],
            )

            style.configure(
                "Treeview",
                background="#151b23",
                fieldbackground="#151b23",
                foreground="#e6edf3",
                rowheight=24,
                borderwidth=0,
            )
            style.map("Treeview", background=[("selected", "#1a2330")], foreground=[("selected", "#ffffff")])
            style.configure("Treeview.Heading", background="#11161d", foreground="#e6edf3", borderwidth=0)

            style.configure("TNotebook", background="#0e1116", borderwidth=0, tabmargins=(0, 0, 0, 0))
            style.configure("TNotebook.Tab", background="#11161d", foreground="#d7e0ea", padding=(16, 10), borderwidth=0)
            style.map(
                "TNotebook.Tab",
                background=[("selected", "#1a2330"), ("active", "#141b24"), ("!selected", "#11161d")],
                foreground=[("selected", "#ffffff"), ("!selected", "#d7e0ea")],
                padding=[("selected", (16, 10)), ("!selected", (16, 10))],
                expand=[("selected", (0, 0, 0, 0)), ("!selected", (0, 0, 0, 0))],
            )

            style.configure(
                "Vertical.TScrollbar",
                background="#11161d",
                troughcolor="#0e1116",
                bordercolor="#0e1116",
                lightcolor="#11161d",
                darkcolor="#11161d",
                arrowcolor="#9fb3c8",
                gripcount=0,
            )
            style.map("Vertical.TScrollbar", background=[("active", "#1a2330"), ("!active", "#11161d")])

        def prompt_new_recovery_password(self) -> Optional[str]:
            first = simpledialog.askstring(
                "Create recovery password",
                "Choose the recovery password for encrypted restores.\n\n"
                "You will need this to restore on another machine or after a full reset.",
                show="*",
            )
            if first is None:
                return None

            second = simpledialog.askstring(
                "Confirm recovery password",
                "Re-enter the recovery password.",
                show="*",
            )
            if second is None:
                return None

            if first != second:
                raise AegisError("Recovery passwords did not match.")

            return validate_recovery_password(first)

        def submit_settings_with_recovery_password_if_needed(self, payload: Dict[str, Any]) -> Dict[str, Any]:
            try:
                response = send_daemon_request({"action": "save_settings", "settings": payload})
                if not response.get("ok"):
                    raise AegisError(response.get("error", "Unknown daemon error"))
                return response
            except Exception as exc:
                if str(exc) != RECOVERY_PASSWORD_REQUIRED_ERROR or not bool(payload.get("encryption_enabled", True)):
                    raise

                recovery_password = self.prompt_new_recovery_password()
                if recovery_password is None:
                    raise AegisError("Recovery password setup was canceled.")

                response = send_daemon_request({
                    "action": "save_settings",
                    "settings": payload,
                    "recovery_password": recovery_password,
                })
                if not response.get("ok"):
                    raise AegisError(response.get("error", "Unknown daemon error"))
                return response
        
        def build_setup_tab(self) -> None:
            frame = ttk.Frame(self.setup_tab)
            frame.pack(fill="both", expand=True)
            frame.grid_columnconfigure(1, weight=1)

            ttk.Label(frame, text="Initial setup", style="Header.TLabel").grid(row=0, column=0, columnspan=3, sticky="w")
            ttk.Label(
                frame,
                text="Finish the core configuration once before exposing backup, restore, peer sync, and advanced settings. You can fine-tune excludes and peer sync later.",
                wraplength=1020,
                style="Muted.TLabel",
            ).grid(row=1, column=0, columnspan=3, sticky="w", pady=(8, 0))

            ttk.Label(frame, text="Machine label").grid(row=2, column=0, sticky="w", padx=(0, 12), pady=(18, 0))
            ttk.Entry(frame, textvariable=self.machine_label_var, width=42).grid(row=2, column=1, sticky="w", pady=(18, 0))

            ttk.Label(frame, text="Backups drive or folder").grid(row=3, column=0, sticky="w", padx=(0, 12), pady=(12, 0))
            ttk.Entry(frame, textvariable=self.repo_path_var, width=54).grid(row=3, column=1, sticky="ew", pady=(12, 0))

            repo_buttons = ttk.Frame(frame)
            repo_buttons.grid(row=3, column=2, sticky="w", padx=(8, 0), pady=(12, 0))
            ttk.Button(
                repo_buttons,
                text="Choose Drive or Folder",
                command=lambda: self.browse_directory(self.repo_path_var),
            ).pack(side="left")

            ttk.Label(
                frame,
                text="Use the chooser to browse folders, open already-mounted drives, or mount an unmounted external USB drive. A Windows-formatted drive is fine as long as Linux can mount it read/write.",
                wraplength=1020,
                style="Muted.TLabel",
            ).grid(row=4, column=0, columnspan=3, sticky="w", pady=(6, 0))

            ttk.Checkbutton(frame, text="Encrypt backups", variable=self.encryption_var).grid(row=5, column=0, columnspan=2, sticky="w", pady=(14, 0))
            ttk.Label(
                frame,
                text="This protects backup data at rest. To allow automatic backups, AegisVault keeps a local root-only unlock key on this machine.",
                wraplength=1020,
                style="Muted.TLabel",
            ).grid(row=6, column=0, columnspan=3, sticky="w", pady=(6, 0))

            ttk.Checkbutton(frame, text="Enable automatic backups", variable=self.schedule_enabled_var).grid(row=7, column=0, columnspan=2, sticky="w", pady=(12, 0))

            ttk.Label(frame, text="Backup schedule").grid(row=8, column=0, sticky="w", padx=(0, 12), pady=(12, 0))
            ttk.Combobox(
                frame,
                textvariable=self.schedule_preset_var,
                values=["manual", "hourly", "daily", "weekly", "custom"],
                width=18,
                state="readonly",
            ).grid(row=8, column=1, sticky="w", pady=(12, 0))

            ttk.Label(frame, text="Custom minutes").grid(row=9, column=0, sticky="w", padx=(0, 12), pady=(12, 0))
            ttk.Entry(frame, textvariable=self.schedule_custom_var, width=12).grid(row=9, column=1, sticky="w", pady=(12, 0))

            ttk.Label(frame, text="I/O yield milliseconds per chunk").grid(row=10, column=0, sticky="w", padx=(0, 12), pady=(12, 0))
            ttk.Entry(frame, textvariable=self.io_yield_var, width=12).grid(row=10, column=1, sticky="w", pady=(12, 0))

            ttk.Checkbutton(
                frame,
                text="Apply package list after portable restore to /",
                variable=self.apply_packages_var,
            ).grid(row=11, column=0, columnspan=2, sticky="w", pady=(12, 0))

            buttons = ttk.Frame(frame)
            buttons.grid(row=12, column=0, columnspan=3, sticky="w", pady=(22, 0))
            ttk.Button(buttons, text="Save Setup and Open App", command=self.complete_onboarding).pack(side="left")

        def apply_configuration_state(self, configured: bool) -> None:
            if self.ui_configured_state == configured:
                return
            self.ui_configured_state = configured

            self.notebook.tab(self.setup_tab, state="hidden" if configured else "normal")
            self.notebook.tab(self.overview_tab, state="normal" if configured else "hidden")
            self.notebook.tab(self.backup_tab, state="normal" if configured else "hidden")
            self.notebook.tab(self.restore_tab, state="normal" if configured else "hidden")
            self.notebook.tab(self.constellation_tab, state="normal" if configured else "hidden")
            self.notebook.tab(self.settings_tab, state="normal" if configured else "hidden")

            if configured:
                self.notebook.select(self.restore_tab if self.recovery_mode else self.overview_tab)
            else:
                self.notebook.select(self.setup_tab)
                self.message_var.set("Finish setup to unlock the rest of AegisVault.")

        def complete_onboarding(self) -> None:
            try:
                payload = self.build_settings_payload(onboarding_complete=True)
                response = self.submit_settings_with_recovery_password_if_needed(payload)
                self.message_var.set(
                    response.get("message", "Setup saved.")
                    + " AegisVault will now keep running in the background using your selected plan."
                )
                self.settings_loaded = False
                self.refresh_dashboard()
            except Exception as exc:
                self.message_var.set(str(exc))

        def style_scrolled_text(self, widget: ScrolledText) -> None:
            widget.configure(
                bg="#151b23",
                fg="#e6edf3",
                insertbackground="#e6edf3",
                relief="flat",
                bd=0,
                highlightthickness=1,
                highlightbackground="#243041",
                highlightcolor="#165dcb",
                padx=8,
                pady=8,
            )
            try:
                widget.vbar.configure(
                    bg="#11161d",
                    activebackground="#1a2330",
                    troughcolor="#0e1116",
                    relief="flat",
                    bd=0,
                    highlightthickness=0,
                    width=12,
                )
            except Exception:
                pass

        def build_overview_tab(self) -> None:
            summary = ttk.Frame(self.overview_tab)
            summary.pack(fill="x")
            self.summary_labels: Dict[str, ttk.Label] = {}
            grid_items = [
                ("machine", "Machine"),
                ("repo", "Backup location"),
                ("last_good", "Last successful backup"),
                ("last_run", "Last attempted backup"),
                ("last_sync", "Last peer sync"),
                ("recovery_key", "Recovery password"),
            ]
            for idx, (key, label) in enumerate(grid_items):
                row = idx // 2
                col = (idx % 2) * 2
                ttk.Label(summary, text=f"{label}:", style="Header.TLabel").grid(row=row, column=col, sticky="w", padx=(0, 8), pady=6)
                value_label = ttk.Label(summary, text="—", wraplength=420)
                value_label.grid(row=row, column=col + 1, sticky="w", padx=(0, 28), pady=6)
                self.summary_labels[key] = value_label

            warnings_frame = ttk.Frame(self.overview_tab)
            warnings_frame.pack(fill="x", pady=(18, 0))
            ttk.Label(warnings_frame, text="Warnings", style="Header.TLabel").pack(anchor="w")
            self.warnings_text = ScrolledText(warnings_frame, height=5, bg="#151b23", fg="#e6edf3", insertbackground="#e6edf3", relief="flat")
            self.warnings_text.pack(fill="x", pady=(8, 0))
            self.style_scrolled_text(self.warnings_text)

            logs_frame = ttk.Frame(self.overview_tab)
            logs_frame.pack(fill="both", expand=True, pady=(18, 0))
            ttk.Label(logs_frame, text="Recent activity", style="Header.TLabel").pack(anchor="w")
            self.logs_text = ScrolledText(logs_frame, height=8, bg="#151b23", fg="#e6edf3", insertbackground="#e6edf3", relief="flat")
            self.logs_text.pack(fill="both", expand=True, pady=(8, 0))
            self.style_scrolled_text(self.logs_text)

        def build_snapshot_table(self, parent: ttk.Frame) -> ttk.Treeview:
            columns = ("created_at", "machine_label", "kind", "bytes", "id")
            tree = ttk.Treeview(parent, columns=columns, show="headings", selectmode="browse", height=10)
            tree.heading("created_at", text="Created")
            tree.heading("machine_label", text="Machine")
            tree.heading("kind", text="Kind")
            tree.heading("bytes", text="Size")
            tree.heading("id", text="Backup ID")
            tree.column("created_at", width=160, anchor="w")
            tree.column("machine_label", width=180, anchor="w")
            tree.column("kind", width=180, anchor="w")
            tree.column("bytes", width=120, anchor="e")
            tree.column("id", width=320, anchor="w")
            tree.bind("<<TreeviewSelect>>", self.on_snapshot_select)
            return tree

        def build_backup_tab(self) -> None:
            controls = ttk.Frame(self.backup_tab)
            controls.pack(fill="x")

            ttk.Label(controls, text="Create backups", style="Header.TLabel").grid(row=0, column=0, columnspan=4, sticky="w")
            ttk.Label(
                controls,
                text="Every backup restores like a full snapshot, but unchanged data chunks are reused across runs to save time and space.",
                wraplength=980,
                style="Muted.TLabel",
            ).grid(row=1, column=0, columnspan=4, sticky="w", pady=(6, 0))

            ttk.Button(controls, text="Run Default Backup", command=self.start_default_backup).grid(row=2, column=0, padx=(0, 8), pady=(12, 0), sticky="w")
            ttk.Button(controls, text="Full Machine Backup", command=lambda: self.start_backup("full_recovery")).grid(row=2, column=1, padx=(0, 8), pady=(12, 0), sticky="w")
            ttk.Button(controls, text="Portable Backup", command=lambda: self.start_backup("portable_state")).grid(row=2, column=2, padx=(0, 8), pady=(12, 0), sticky="w")
            ttk.Button(controls, text="Both Backup Types", command=lambda: self.start_backup("both")).grid(row=2, column=3, padx=(0, 8), pady=(12, 0), sticky="w")

            snaps = ttk.Frame(self.backup_tab)
            snaps.pack(fill="both", expand=True, pady=(18, 0))
            ttk.Label(snaps, text="Saved backups", style="Header.TLabel").pack(anchor="w")
            self.backup_tree = self.build_snapshot_table(snaps)
            self.backup_tree.pack(fill="both", expand=True, pady=(8, 0))

            snap_actions = ttk.Frame(snaps)
            snap_actions.pack(fill="x", pady=(10, 0))
            ttk.Button(snap_actions, text="Delete Selected Backup", command=self.delete_selected_snapshot).pack(side="left")
            ttk.Button(snap_actions, text="↻ Refresh", command=self.refresh_dashboard).pack(side="left", padx=(8, 0))

            export = ttk.Frame(self.backup_tab)
            export.pack(fill="x", pady=(18, 0))
            ttk.Label(export, text="Export selected backup as an encrypted file", style="Header.TLabel").grid(row=0, column=0, columnspan=2, sticky="w")

            ttk.Label(export, text="Bundle password").grid(row=1, column=0, sticky="w", padx=(0, 12), pady=(12, 0))
            ttk.Entry(export, textvariable=self.export_password_var, show="*", width=34).grid(row=1, column=1, sticky="w", pady=(12, 0))

            ttk.Label(export, text="Recovery password for foreign machine snapshot (optional)").grid(row=2, column=0, sticky="w", padx=(0, 12), pady=(12, 0))
            ttk.Entry(export, textvariable=self.export_recovery_key_var, width=34).grid(row=2, column=1, sticky="w", pady=(12, 0))

            ttk.Button(export, text="Choose Output and Export", command=self.export_selected_bundle).grid(row=3, column=1, sticky="w", pady=(14, 0))

        def build_restore_tab(self) -> None:
            intro = ttk.Frame(self.restore_tab)
            intro.pack(fill="x")
            ttk.Label(intro, text="Restore and recovery", style="Header.TLabel").grid(row=0, column=0, columnspan=5, sticky="w")
            intro_text = (
                "Use Portable restore inside a running Linux install, or use Guided Full Restore from recovery media "
                "to wipe a disk and put a Full Recovery snapshot back exactly. "
                "You can also restore from an encrypted bundle file or a hosted bundle URL."
            )
            ttk.Label(intro, text=intro_text, wraplength=1080, style="Muted.TLabel").grid(row=1, column=0, columnspan=5, sticky="w", pady=(6, 0))
            ttk.Label(intro, text="Backups drive or folder").grid(row=2, column=0, sticky="w", pady=(12, 0))
            ttk.Entry(intro, textvariable=self.repo_source_var, width=58).grid(row=2, column=1, sticky="w", pady=(12, 0))
            ttk.Button(intro, text="Choose Drive or Folder", command=lambda: self.browse_directory(self.repo_source_var)).grid(row=2, column=2, padx=(8, 0), pady=(12, 0))
            ttk.Button(intro, text="Use This Location", command=self.use_repo_source_path).grid(row=2, column=3, padx=(8, 0), pady=(12, 0))
            ttk.Button(intro, text="Scan for Backup Drives", command=lambda: self.scan_repository_candidates(auto_use=False)).grid(row=2, column=4, padx=(8, 0), pady=(12, 0))
            ttk.Label(intro, text="Detected backup drives").grid(row=3, column=0, sticky="w", pady=(10, 0))
            self.repo_candidate_combo = ttk.Combobox(intro, textvariable=self.repo_candidate_var, width=56, state="readonly")
            self.repo_candidate_combo.grid(row=3, column=1, sticky="w", pady=(10, 0))
            ttk.Button(intro, text="Use Selected", command=self.use_selected_repo_candidate).grid(row=3, column=2, padx=(8, 0), pady=(10, 0))

            ttk.Separator(self.restore_tab, orient="horizontal").pack(fill="x", pady=18)

            helper = ttk.Frame(self.restore_tab)
            helper.pack(fill="x")
            if self.recovery_mode:
                ttk.Label(helper, text="Guided Full Restore (recommended)", style="Header.TLabel").grid(row=0, column=0, columnspan=4, sticky="w")
                ttk.Label(helper, text="Select the destination disk. AegisVault will wipe it, recreate a bootable layout, restore the Full Recovery snapshot, refresh initramfs, and reinstall the bootloader.", wraplength=1080, style="Muted.TLabel").grid(row=1, column=0, columnspan=4, sticky="w", pady=(6, 0))
                device_row = ttk.Frame(helper)
                device_row.grid(row=2, column=0, columnspan=3, sticky="w", pady=(12, 0))

                ttk.Label(device_row, text="Target disk").pack(side="left")
                self.guided_disk_combo = ttk.Combobox(device_row, textvariable=self.guided_target_disk_var, width=54, state="readonly")
                self.guided_disk_combo.pack(side="left", padx=(12, 8))
                ttk.Button(device_row, text="↻ Refresh", command=self.refresh_local_device_lists).pack(side="left")
                ttk.Button(helper, text="Restore Selected Snapshot to Disk", command=self.guided_restore_repo).grid(row=3, column=1, sticky="w", pady=(12, 0))
                ttk.Button(helper, text="Restore Bundle or URL to Disk", command=self.guided_restore_bundle).grid(row=3, column=2, sticky="w", padx=(8, 0), pady=(12, 0))
            else:
                ttk.Label(helper, text="Create Recovery USB for Full Recovery snapshots", style="Header.TLabel").grid(row=0, column=0, columnspan=4, sticky="w")
                ttk.Label(helper, text="Plug in an empty 8–16 GB USB drive. AegisVault will build a bootable Debian-based recovery environment that starts straight into the restore UI so a casual user can click through a full-machine restore.", wraplength=1080, style="Muted.TLabel").grid(row=1, column=0, columnspan=4, sticky="w", pady=(6, 0))
                device_row = ttk.Frame(helper)
                device_row.grid(row=2, column=0, columnspan=3, sticky="w", pady=(12, 0))

                ttk.Label(device_row, text="Recovery USB device").pack(side="left")
                self.recovery_usb_combo = ttk.Combobox(device_row, textvariable=self.recovery_usb_device_var, width=54, state="readonly")
                self.recovery_usb_combo.pack(side="left", padx=(12, 8))
                ttk.Button(device_row, text="↻ Refresh", command=self.refresh_local_device_lists).pack(side="left")

                ttk.Button(helper, text="Create Recovery USB", command=self.create_recovery_usb_from_gui).grid(row=3, column=1, sticky="w", pady=(12, 0))

            ttk.Separator(self.restore_tab, orient="horizontal").pack(fill="x", pady=18)

            repo_section = ttk.Frame(self.restore_tab)
            repo_section.pack(fill="x")
            ttk.Label(repo_section, text="Restore from saved backup", style="Header.TLabel").grid(row=0, column=0, columnspan=4, sticky="w")
            self.restore_tree = self.build_snapshot_table(repo_section)
            self.restore_tree.grid(row=1, column=0, columnspan=4, sticky="nsew", pady=(8, 0))
            repo_section.grid_columnconfigure(0, weight=1)
            repo_section.grid_rowconfigure(1, weight=1)

            ttk.Label(repo_section, text="Target path").grid(row=2, column=0, sticky="w", padx=(0, 12), pady=(12, 0))
            ttk.Entry(repo_section, textvariable=self.repo_restore_target_var, width=46).grid(row=2, column=1, sticky="w", pady=(12, 0))
            ttk.Button(repo_section, text="Browse", command=lambda: self.browse_directory(self.repo_restore_target_var)).grid(row=2, column=2, padx=(8, 0), pady=(12, 0))

            ttk.Label(repo_section, text="Only restore this path (optional)").grid(row=3, column=0, sticky="w", padx=(0, 12), pady=(12, 0))
            ttk.Entry(repo_section, textvariable=self.repo_restore_path_var, width=46).grid(row=3, column=1, sticky="w", pady=(12, 0))

            ttk.Label(repo_section, text="Recovery password (only needed for other machine snapshots)").grid(row=4, column=0, sticky="w", padx=(0, 12), pady=(12, 0))
            ttk.Entry(repo_section, textvariable=self.repo_recovery_key_var, width=46).grid(row=4, column=1, sticky="w", pady=(12, 0))

            ttk.Button(
                repo_section,
                text="Restore Selected\nSnapshot",
                width=20,
                command=self.restore_repo_snapshot,
            ).grid(row=5, column=1, sticky="w", pady=(14, 0))

            ttk.Separator(self.restore_tab, orient="horizontal").pack(fill="x", pady=18)

            bundle_section = ttk.Frame(self.restore_tab)
            bundle_section.pack(fill="x")
            ttk.Label(bundle_section, text="Restore from encrypted single-file bundle or hosted URL", style="Header.TLabel").grid(row=0, column=0, columnspan=4, sticky="w")
            ttk.Label(bundle_section, text="Bundle file").grid(row=1, column=0, sticky="w", pady=(12, 0))
            ttk.Entry(bundle_section, textvariable=self.bundle_file_var, width=60).grid(row=1, column=1, sticky="w", pady=(12, 0))
            ttk.Button(bundle_section, text="Browse", command=lambda: self.browse_file(self.bundle_file_var)).grid(row=1, column=2, padx=(8, 0), pady=(12, 0))
            ttk.Label(bundle_section, text="Hosted URL").grid(row=2, column=0, sticky="w", pady=(12, 0))
            ttk.Entry(bundle_section, textvariable=self.bundle_url_var, width=60).grid(row=2, column=1, sticky="w", pady=(12, 0))
            ttk.Label(bundle_section, text="Bundle password").grid(row=3, column=0, sticky="w", pady=(12, 0))
            ttk.Entry(bundle_section, textvariable=self.bundle_password_var, show="*", width=42).grid(row=3, column=1, sticky="w", pady=(12, 0))
            ttk.Label(bundle_section, text="Target path").grid(row=4, column=0, sticky="w", pady=(12, 0))
            ttk.Entry(bundle_section, textvariable=self.bundle_restore_target_var, width=42).grid(row=4, column=1, sticky="w", pady=(12, 0))
            ttk.Button(bundle_section, text="Browse", command=lambda: self.browse_directory(self.bundle_restore_target_var)).grid(row=4, column=2, padx=(8, 0), pady=(12, 0))
            ttk.Label(bundle_section, text="Selective path inside snapshot").grid(row=5, column=0, sticky="w", pady=(12, 0))
            ttk.Entry(bundle_section, textvariable=self.bundle_restore_path_var, width=42).grid(row=5, column=1, sticky="w", pady=(12, 0))
            ttk.Button(bundle_section, text="Restore Bundle", command=self.restore_bundle).grid(row=5, column=2, padx=(8, 0), pady=(12, 0))
            if self.recovery_mode:
                ttk.Button(bundle_section, text="Guided Full Restore Bundle to Disk", command=self.guided_restore_bundle).grid(row=5, column=3, padx=(8, 0), pady=(12, 0))

        def build_constellation_tab(self) -> None:
            info = ttk.Frame(self.constellation_tab)
            info.pack(fill="x")
            ttk.Label(info, text="Constellation Mode", style="Header.TLabel").pack(anchor="w")
            ttk.Label(
                info,
                text="Mirror encrypted backup repositories across your configured peers over SSH and rsync. Each peer stores ciphertext, and every node can pull everyone else's backup namespaces.",
                wraplength=1040,
                style="Muted.TLabel",
            ).pack(anchor="w", pady=(8, 0))
            ttk.Button(info, text="Sync Peers Now", command=self.sync_peers_now).pack(anchor="w", pady=(12, 0))

            peers_frame = ttk.Frame(self.constellation_tab)
            peers_frame.pack(fill="both", expand=True, pady=(18, 0))
            ttk.Label(peers_frame, text="Configured peers", style="Header.TLabel").pack(anchor="w")
            columns = ("enabled", "label", "target", "repo", "port")
            self.peers_tree = ttk.Treeview(peers_frame, columns=columns, show="headings", height=12)
            for key, title, width in [
                ("enabled", "Enabled", 80),
                ("label", "Label", 180),
                ("target", "SSH Target", 220),
                ("repo", "Repository", 320),
                ("port", "Port", 80),
            ]:
                self.peers_tree.heading(key, text=title)
                self.peers_tree.column(key, width=width, anchor="w")
            self.peers_tree.pack(fill="both", expand=True, pady=(8, 0))

        def build_settings_tab(self) -> None:
            outer = ttk.Frame(self.settings_tab)
            outer.pack(fill="both", expand=True)

            left = ttk.Frame(outer)
            left.pack(side="left", fill="both", expand=True, padx=(0, 10))
            right = ttk.Frame(outer)
            right.pack(side="left", fill="both", expand=True)

            general = ttk.Frame(left)
            general.pack(fill="x")
            general.grid_columnconfigure(1, weight=1)

            ttk.Label(general, text="General", style="Header.TLabel").grid(row=0, column=0, columnspan=3, sticky="w")
            ttk.Label(general, text="Machine label").grid(row=1, column=0, sticky="w", padx=(0, 12), pady=(10, 0))
            ttk.Entry(general, textvariable=self.machine_label_var, width=40).grid(row=1, column=1, sticky="w", pady=(10, 0))

            ttk.Label(general, text="Backup storage folder").grid(row=2, column=0, sticky="w", padx=(0, 12), pady=(10, 0))
            repo_row = ttk.Frame(general)
            repo_row.grid(row=2, column=1, columnspan=2, sticky="w", pady=(10, 0))
            ttk.Entry(repo_row, textvariable=self.repo_path_var, width=40).pack(side="left")
            ttk.Button(repo_row, text="Browse", command=lambda: self.browse_directory(self.repo_path_var)).pack(side="left", padx=(8, 0))

            ttk.Checkbutton(general, text="Encrypt backups", variable=self.encryption_var).grid(row=3, column=0, columnspan=2, sticky="w", pady=(10, 0))
            ttk.Checkbutton(general, text="Apply package list after portable restore to /", variable=self.apply_packages_var).grid(row=4, column=0, columnspan=2, sticky="w", pady=(10, 0))

            schedule = ttk.Frame(left)
            schedule.pack(fill="x", pady=(24, 0))
            ttk.Label(schedule, text="Scheduling and smoothing", style="Header.TLabel").grid(row=0, column=0, columnspan=3, sticky="w")
            ttk.Checkbutton(schedule, text="Enable automatic backups", variable=self.schedule_enabled_var).grid(row=1, column=0, columnspan=2, sticky="w", pady=(10, 0))

            ttk.Label(schedule, text="Preset").grid(row=2, column=0, sticky="w", pady=(10, 0))
            ttk.Combobox(
                schedule,
                textvariable=self.schedule_preset_var,
                values=["manual", "hourly", "daily", "weekly", "custom"],
                width=18,
                state="readonly",
            ).grid(row=2, column=1, sticky="w", pady=(10, 0))

            ttk.Label(schedule, text="Custom minutes").grid(row=3, column=0, sticky="w", pady=(10, 0))
            ttk.Entry(schedule, textvariable=self.schedule_custom_var, width=12).grid(row=3, column=1, sticky="w", pady=(10, 0))

            ttk.Label(schedule, text="I/O yield milliseconds per chunk").grid(row=4, column=0, sticky="w", pady=(10, 0))
            ttk.Entry(schedule, textvariable=self.io_yield_var, width=12).grid(row=4, column=1, sticky="w", pady=(10, 0))

            ttk.Label(schedule, text="Default backup plan").grid(row=5, column=0, sticky="w", pady=(10, 0))
            profile_row = ttk.Frame(schedule)
            profile_row.grid(row=5, column=1, sticky="w", pady=(10, 0))
            ttk.Radiobutton(profile_row, text="Full machine", variable=self.default_backup_profile_var, value="full_recovery").pack(side="left")
            ttk.Radiobutton(profile_row, text="Portable", variable=self.default_backup_profile_var, value="portable_state").pack(side="left", padx=(12, 0))
            ttk.Radiobutton(profile_row, text="Both", variable=self.default_backup_profile_var, value="both").pack(side="left", padx=(12, 0))

            ttk.Checkbutton(schedule, text="Show desktop notifications", variable=self.notifications_enabled_var).grid(
                row=6, column=0, columnspan=2, sticky="w", pady=(10, 0)
            )
            ttk.Label(
                schedule,
                text="Desktop notifications warn about starts, finishes, and problems such as missing backup drives.",
                wraplength=420,
                style="Muted.TLabel",
            ).grid(row=7, column=0, columnspan=2, sticky="w", pady=(6, 0))

            excludes = ttk.Frame(left)
            excludes.pack(fill="both", expand=True, pady=(24, 0))
            ttk.Label(excludes, text="Full Recovery excludes", style="Header.TLabel").pack(anchor="w")
            self.full_excludes_text = ScrolledText(excludes, height=8, bg="#151b23", fg="#e6edf3", insertbackground="#e6edf3", relief="flat")
            self.full_excludes_text.pack(fill="both", expand=True, pady=(8, 0))
            self.style_scrolled_text(self.full_excludes_text)
            ttk.Label(excludes, text="Portable includes", style="Header.TLabel").pack(anchor="w", pady=(18, 0))
            self.portable_includes_text = ScrolledText(excludes, height=6, bg="#151b23", fg="#e6edf3", insertbackground="#e6edf3", relief="flat")
            self.portable_includes_text.pack(fill="both", expand=True, pady=(8, 0))
            self.style_scrolled_text(self.portable_includes_text)
            ttk.Label(excludes, text="Portable excludes", style="Header.TLabel").pack(anchor="w", pady=(18, 0))
            self.portable_excludes_text = ScrolledText(excludes, height=8, bg="#151b23", fg="#e6edf3", insertbackground="#e6edf3", relief="flat")
            self.portable_excludes_text.pack(fill="both", expand=True, pady=(8, 0))
            self.style_scrolled_text(self.portable_excludes_text)

            peers = ttk.Frame(right)
            peers.pack(fill="both", expand=True)
            ttk.Label(peers, text="Constellation peer configuration", style="Header.TLabel").grid(row=0, column=0, columnspan=3, sticky="w")
            ttk.Checkbutton(peers, text="Enable Constellation mirror sync", variable=self.peers_enabled_var).grid(row=1, column=0, columnspan=3, sticky="w", pady=(10, 0))

            ttk.Label(peers, text="Label").grid(row=2, column=0, sticky="w", pady=(10, 0))
            ttk.Entry(peers, textvariable=self.peer_label_var, width=24).grid(row=2, column=1, sticky="w", pady=(10, 0))
            ttk.Label(peers, text="SSH target").grid(row=3, column=0, sticky="w", pady=(10, 0))
            ttk.Entry(peers, textvariable=self.peer_target_var, width=30).grid(row=3, column=1, sticky="w", pady=(10, 0))
            ttk.Label(peers, text="Peer repo path").grid(row=4, column=0, sticky="w", pady=(10, 0))
            ttk.Entry(peers, textvariable=self.peer_repo_var, width=30).grid(row=4, column=1, sticky="w", pady=(10, 0))
            ttk.Label(peers, text="Port").grid(row=5, column=0, sticky="w", pady=(10, 0))
            ttk.Entry(peers, textvariable=self.peer_port_var, width=8).grid(row=5, column=1, sticky="w", pady=(10, 0))
            ttk.Label(peers, text="Identity file").grid(row=6, column=0, sticky="w", pady=(10, 0))
            ttk.Entry(peers, textvariable=self.peer_identity_var, width=30).grid(row=6, column=1, sticky="w", pady=(10, 0))
            ttk.Button(peers, text="Browse", command=lambda: self.browse_file(self.peer_identity_var)).grid(row=6, column=2, padx=(8, 0), pady=(10, 0))
            ttk.Button(peers, text="Add or Update Peer", command=self.add_peer_from_form).grid(row=7, column=0, columnspan=2, sticky="w", pady=(12, 0))
            ttk.Button(peers, text="Remove Selected Peer", command=self.remove_selected_peer).grid(row=7, column=2, sticky="w", pady=(12, 0))
            columns = ("label", "target", "repo", "port", "identity", "enabled")
            self.settings_peers_tree = ttk.Treeview(peers, columns=columns, show="headings", height=11)
            for key, title, width in [
                ("label", "Label", 120),
                ("target", "SSH Target", 170),
                ("repo", "Repo Path", 180),
                ("port", "Port", 60),
                ("identity", "Identity File", 180),
                ("enabled", "Enabled", 80),
            ]:
                self.settings_peers_tree.heading(key, text=title)
                self.settings_peers_tree.column(key, width=width, anchor="w")
            self.settings_peers_tree.grid(row=8, column=0, columnspan=3, sticky="nsew", pady=(16, 0))
            peers.grid_rowconfigure(8, weight=1)
            peers.grid_columnconfigure(1, weight=1)
            self.settings_peers_tree.bind("<<TreeviewSelect>>", self.on_peer_select)

            ttk.Button(right, text="Save Settings", command=self.save_settings).pack(anchor="w", pady=(18, 0))

        def browse_directory(self, variable: tk.StringVar) -> None:
            start_path = variable.get().strip() or self.repo_path_var.get().strip() or "/"
            chosen = self.open_directory_chooser(start_path)
            if chosen:
                variable.set(chosen)
        
        def open_directory_chooser(self, start_path: str) -> Optional[str]:
            dialog = tk.Toplevel(self.root)
            dialog.title("Choose Drive or Folder")
            dialog.geometry("960x700")
            dialog.minsize(840, 560)
            dialog.configure(bg="#0e1116")
            dialog.transient(self.root)
            dialog.grab_set()

            initial_path = start_path if os.path.isdir(start_path) else "/"
            current_path_var = tk.StringVar(value=os.path.abspath(initial_path))
            result: Dict[str, Optional[str]] = {"path": None}
            root_items: List[Dict[str, str]] = []
            child_items: List[str] = []

            header = ttk.Frame(dialog, padding=16)
            header.pack(fill="x")
            ttk.Label(header, text="Choose where backups live", style="Header.TLabel").pack(anchor="w")
            ttk.Label(
                header,
                text="Select a drive or folder on the left. Unmounted external drives can be mounted from here.",
                wraplength=900,
                style="Muted.TLabel",
            ).pack(anchor="w", pady=(6, 0))

            body = ttk.Frame(dialog, padding=(16, 0, 16, 16))
            body.pack(fill="both", expand=True)
            body.grid_columnconfigure(0, weight=1)
            body.grid_columnconfigure(1, weight=2)
            body.grid_rowconfigure(1, weight=1)

            ttk.Label(body, text="Drives and locations").grid(row=0, column=0, sticky="w", pady=(0, 8))
            ttk.Label(body, text="Folders in current location").grid(row=0, column=1, sticky="w", padx=(12, 0), pady=(0, 8))

            roots_frame = ttk.Frame(body)
            roots_frame.grid(row=1, column=0, sticky="nsew")
            children_frame = ttk.Frame(body)
            children_frame.grid(row=1, column=1, sticky="nsew", padx=(12, 0))

            roots_list = tk.Listbox(
                roots_frame,
                bg="#0b0f14",
                fg="#ffffff",
                selectbackground="#1a2330",
                selectforeground="#ffffff",
                activestyle="none",
                exportselection=False,
                relief="flat",
                bd=0,
                highlightthickness=1,
                highlightbackground="#243041",
                highlightcolor="#165dcb",
            )
            roots_scroll = ttk.Scrollbar(roots_frame, orient="vertical", command=roots_list.yview)
            roots_list.configure(yscrollcommand=roots_scroll.set)
            roots_list.pack(side="left", fill="both", expand=True)
            roots_scroll.pack(side="right", fill="y")

            children_list = tk.Listbox(
                children_frame,
                bg="#0b0f14",
                fg="#ffffff",
                selectbackground="#1a2330",
                selectforeground="#ffffff",
                activestyle="none",
                exportselection=False,
                relief="flat",
                bd=0,
                highlightthickness=1,
                highlightbackground="#243041",
                highlightcolor="#165dcb",
            )
            children_scroll = ttk.Scrollbar(children_frame, orient="vertical", command=children_list.yview)
            children_list.configure(yscrollcommand=children_scroll.set)
            children_list.pack(side="left", fill="both", expand=True)
            children_scroll.pack(side="right", fill="y")

            current_bar = ttk.Frame(dialog, padding=(16, 0, 16, 10))
            current_bar.pack(fill="x")
            ttk.Label(current_bar, text="Current folder").pack(side="left")
            current_entry = tk.Entry(
                current_bar,
                textvariable=current_path_var,
                bg="#0b0f14",
                fg="#ffffff",
                insertbackground="#ffffff",
                readonlybackground="#0b0f14",
                relief="flat",
                bd=0,
            )
            current_entry.configure(state="readonly")
            current_entry.pack(side="left", fill="x", expand=True, padx=(12, 0))

            def available_roots() -> List[Dict[str, str]]:
                rows: List[Dict[str, str]] = []
                seen_paths: Set[str] = set()
                seen_devices: Set[str] = set()
                root_disk = current_root_disk()
                entries = list_block_devices()
                entries_by_path = {entry.get("path", ""): entry for entry in entries}

                for entry in entries:
                    if entry.get("type") not in {"disk", "part"}:
                        continue

                    device_path = entry.get("path", "")
                    if not device_path or device_path in seen_devices:
                        continue
                    seen_devices.add(device_path)

                    parent_disk = device_parent_disk(device_path)
                    if device_path == root_disk or parent_disk == root_disk:
                        continue

                    parent_entry = entries_by_path.get(parent_disk, {})
                    mountpoints = [os.path.abspath(mp) for mp in (entry.get("mountpoints") or []) if mp]
                    is_external = (
                        bool(entry.get("removable"))
                        or entry.get("transport") == "usb"
                        or bool(parent_entry.get("removable"))
                        or parent_entry.get("transport") == "usb"
                        or any(mp.startswith(EXTERNAL_BACKUP_ROOT_PREFIXES) for mp in mountpoints)
                    )
                    if not is_external:
                        continue

                    fstype = (entry.get("fstype") or "").strip()
                    if not mountpoints and fstype in {"", "swap", "crypto_LUKS", "LVM2_member"}:
                        continue

                    label = (
                        entry.get("label")
                        or entry.get("model")
                        or parent_entry.get("label")
                        or parent_entry.get("model")
                        or parent_entry.get("serial")
                        or Path(device_path).name
                    )
                    size_text = human_bytes(int(entry.get("size") or 0))

                    if mountpoints:
                        mountpoint = mountpoints[0]
                        if mountpoint not in seen_paths:
                            seen_paths.add(mountpoint)
                            rows.append({
                                "kind": "mounted",
                                "label": f"Drive: {label} | {fstype or 'unknown fs'} | {size_text} | {mountpoint}",
                                "path": mountpoint,
                                "device": device_path,
                            })
                    else:
                        rows.append({
                            "kind": "unmounted",
                            "label": f"Drive: {label} | {fstype or 'unknown fs'} | {size_text} | {device_path} | not mounted",
                            "path": "",
                            "device": device_path,
                        })

                for fallback in [os.path.abspath(initial_path), "/", "/media", "/mnt", "/run/media", str(Path.home())]:
                    folder = os.path.abspath(fallback)
                    if os.path.isdir(folder) and folder not in seen_paths:
                        seen_paths.add(folder)
                        rows.append({
                            "kind": "folder",
                            "label": f"Folder: {folder}",
                            "path": folder,
                            "device": "",
                        })

                rows.sort(key=lambda item: (0 if item["label"].startswith("Drive:") else 1, item["label"].lower()))
                return rows

            def refresh_roots() -> None:
                roots_list.delete(0, "end")
                root_items.clear()
                root_items.extend(available_roots())
                for item in root_items:
                    roots_list.insert("end", item["label"])
                update_action_buttons()

            def set_current_path(path: str) -> None:
                path = os.path.abspath(path)
                if not os.path.isdir(path):
                    return

                current_path_var.set(path)
                children_list.delete(0, "end")
                child_items.clear()

                try:
                    names = sorted(
                        [name for name in os.listdir(path) if os.path.isdir(os.path.join(path, name))],
                        key=str.lower,
                    )
                except (PermissionError, FileNotFoundError, NotADirectoryError, OSError) as exc:
                    names = []
                    self.message_var.set(f"Could not read folders in {path}: {exc}")

                for name in names:
                    full = os.path.join(path, name)
                    child_items.append(full)
                    children_list.insert("end", name)

                children_list.selection_clear(0, "end")
                update_action_buttons()

            def preview_selected_root(event=None) -> None:
                update_action_buttons()
                selection = roots_list.curselection()
                if not selection:
                    return

                item = root_items[selection[0]]
                if item["kind"] in {"mounted", "folder"} and item.get("path"):
                    set_current_path(item["path"])

            def preview_selected_child(event=None) -> None:
                update_action_buttons()
                selection = children_list.curselection()
                if not selection:
                    return

                chosen = child_items[selection[0]]
                if os.path.isdir(chosen):
                    set_current_path(chosen)
            
            def open_selected_child(event=None) -> None:
                selection = children_list.curselection()
                if not selection:
                    return
                set_current_path(child_items[selection[0]])

            def act_on_selected_root(event=None) -> None:
                selection = roots_list.curselection()
                if not selection:
                    return

                item = root_items[selection[0]]
                kind = item["kind"]

                if kind in {"mounted", "folder"}:
                    set_current_path(item["path"])
                    return

                try:
                    response = send_daemon_request({
                        "action": "mount_backup_device",
                        "device": item["device"],
                    })
                    if not response.get("ok"):
                        raise AegisError(response.get("error", "Unknown daemon error"))

                    mounted_path = str(response.get("mountpoint") or "").strip()
                    if not mounted_path:
                        raise AegisError("Mount completed, but no mount path was returned.")

                    refresh_roots()
                    set_current_path(mounted_path)

                    for index, row in enumerate(root_items):
                        if os.path.abspath(row.get("path", "")) == os.path.abspath(mounted_path):
                            roots_list.selection_clear(0, "end")
                            roots_list.selection_set(index)
                            roots_list.activate(index)
                            roots_list.see(index)
                            break

                    update_action_buttons()
                except Exception as exc:
                    messagebox.showerror("Mount failed", str(exc), parent=dialog)

            def go_up() -> None:
                current = current_path_var.get().strip() or "/"
                parent = os.path.dirname(current.rstrip("/")) or "/"
                set_current_path(parent)

            def refresh_current_view() -> None:
                current = current_path_var.get().strip() or "/"
                refresh_roots()
                set_current_path(current)

            def create_current_folder() -> None:
                parent_path = current_path_var.get().strip() or "/"
                folder_name = simpledialog.askstring(
                    "Create Folder",
                    f"New folder name inside:\n{parent_path}",
                    parent=dialog,
                )
                if folder_name is None:
                    return

                folder_name = folder_name.strip()
                if not folder_name:
                    self.message_var.set("Folder name cannot be empty.")
                    return
                if folder_name in {".", ".."} or "/" in folder_name or "\x00" in folder_name:
                    self.message_var.set("Choose a folder name without slashes.")
                    return

                new_path = os.path.join(parent_path, folder_name)

                try:
                    os.mkdir(new_path)
                except FileExistsError:
                    self.message_var.set(f"Folder already exists: {new_path}")
                    set_current_path(new_path)
                    return
                except Exception as exc:
                    messagebox.showerror("Create Folder Failed", str(exc), parent=dialog)
                    self.message_var.set(f"Could not create folder in {parent_path}: {exc}")
                    return

                self.message_var.set(f"Created folder: {new_path}")
                refresh_roots()
                set_current_path(new_path)
            
            def choose_current() -> None:
                current = current_path_var.get().strip()
                if current:
                    result["path"] = current
                    dialog.destroy()

            buttons = ttk.Frame(dialog, padding=(16, 0, 16, 16))
            buttons.pack(fill="x")

            left_actions = ttk.Frame(buttons)
            left_actions.pack(side="left")

            root_action_btn = ttk.Button(left_actions, text="Open Selected Drive", command=act_on_selected_root)
            folder_action_btn = ttk.Button(left_actions, text="Open Selected Folder", command=open_selected_child)

            ttk.Button(buttons, text="Up", command=go_up).pack(side="left", padx=(8, 0))
            ttk.Button(buttons, text="↻", width=3, command=refresh_current_view).pack(side="left", padx=(8, 0))
            ttk.Button(buttons, text="New Folder", command=create_current_folder).pack(side="left", padx=(8, 0))
            ttk.Button(buttons, text="Choose This Folder", command=choose_current).pack(side="right")
            ttk.Button(buttons, text="Cancel", command=dialog.destroy).pack(side="right", padx=(0, 8))

            def update_action_buttons(event=None) -> None:
                root_selection = roots_list.curselection()
                if root_selection:
                    item = root_items[root_selection[0]]
                    if item["kind"] == "unmounted":
                        root_action_btn.configure(text="Mount Selected Drive")
                    elif item["kind"] == "folder":
                        root_action_btn.configure(text="Open Selected Location")
                    else:
                        root_action_btn.configure(text="Open Selected Drive")

                    if not root_action_btn.winfo_ismapped():
                        root_action_btn.pack(side="left")
                else:
                    if root_action_btn.winfo_ismapped():
                        root_action_btn.pack_forget()

                child_selection = children_list.curselection()
                if child_selection:
                    folder_action_btn.configure(text="Open Selected Folder")
                    if not folder_action_btn.winfo_ismapped():
                        folder_action_btn.pack(side="left", padx=(8, 0))
                else:
                    if folder_action_btn.winfo_ismapped():
                        folder_action_btn.pack_forget()

            roots_list.bind("<<ListboxSelect>>", preview_selected_root)
            children_list.bind("<<ListboxSelect>>", preview_selected_child)
            roots_list.bind("<Double-Button-1>", act_on_selected_root)
            children_list.bind("<Double-Button-1>", open_selected_child)

            refresh_roots()
            set_current_path(current_path_var.get())
            dialog.wait_window()
            return result["path"]
        
        def browse_file(self, variable: tk.StringVar) -> None:
            value = filedialog.askopenfilename()
            if value:
                variable.set(value)

        def refresh_local_device_lists(self) -> None:
            try:
                usb_choices = list_disk_choices(exclude_paths={current_root_disk()}, removable_only=True)
                guided_choices = list_disk_choices(exclude_paths={current_root_disk()}, removable_only=False)

                self.usb_choice_map = {item["display"]: item["path"] for item in usb_choices}
                self.guided_disk_map = {item["display"]: item["path"] for item in guided_choices}

                if hasattr(self, "recovery_usb_combo"):
                    self.recovery_usb_combo.configure(values=list(self.usb_choice_map.keys()))
                if hasattr(self, "guided_disk_combo"):
                    self.guided_disk_combo.configure(values=list(self.guided_disk_map.keys()))

                if usb_choices and self.recovery_usb_device_var.get() not in self.usb_choice_map:
                    self.recovery_usb_device_var.set(usb_choices[0]["display"])
                if guided_choices and self.guided_target_disk_var.get() not in self.guided_disk_map:
                    self.guided_target_disk_var.set(guided_choices[0]["display"])
            except Exception as exc:
                self.message_var.set(str(exc))
        
        def refresh_backup_location_suggestions(self) -> None:
            try:
                choices = discover_backup_location_choices()
                self.storage_choice_map = {item["label"]: item["path"] for item in choices}
                self.storage_choices = list(self.storage_choice_map.keys())

                if hasattr(self, "storage_choice_combo"):
                    self.storage_choice_combo.configure(values=self.storage_choices)

                if self.storage_choices:
                    if self.storage_choice_var.get() not in self.storage_choice_map:
                        self.storage_choice_var.set(self.storage_choices[0])
                    return

                entries = list_block_devices()
                entries_by_path = {entry.get("path", ""): entry for entry in entries}
                root_disk = current_root_disk()
                unmounted_external_parts: List[str] = []

                for entry in entries:
                    if entry.get("type") != "part":
                        continue
                    if entry.get("mountpoints"):
                        continue

                    part_path = entry.get("path", "")
                    parent_disk = device_parent_disk(part_path)
                    if parent_disk == root_disk:
                        continue

                    parent_entry = entries_by_path.get(parent_disk, {})
                    is_external = (
                        bool(entry.get("removable"))
                        or entry.get("transport") == "usb"
                        or bool(parent_entry.get("removable"))
                        or parent_entry.get("transport") == "usb"
                    )
                    if not is_external:
                        continue

                    label = entry.get("label") or parent_entry.get("model") or Path(part_path).name
                    fs_name = entry.get("fstype") or "unknown fs"
                    size_text = human_bytes(int(entry.get("size") or 0))
                    unmounted_external_parts.append(f"{part_path} | {label} | {fs_name} | {size_text}")

                if unmounted_external_parts:
                    self.storage_choice_var.set("")
                    self.message_var.set(
                        "External drive detected, but it is not mounted yet: "
                        + "; ".join(unmounted_external_parts[:3])
                        + ". Open it in Files or mount it in Disks, then click Refresh Drives."
                    )
                else:
                    self.storage_choice_var.set("")
                    self.message_var.set(
                        "No mounted backup drives were detected yet. Plug in the drive, wait for Linux to mount it, then click Refresh Drives or Choose Drive or Folder."
                    )
            except Exception as exc:
                self.message_var.set(str(exc))

        def apply_suggested_backup_location(self) -> None:
            chosen = self.storage_choice_map.get(self.storage_choice_var.get().strip(), "").strip()
            if not chosen:
                self.message_var.set("Choose a detected backup drive first, or use Choose Drive or Folder.")
                return
            self.repo_path_var.set(chosen)
            self.message_var.set(f"Backup location set to {chosen}")

        def scan_repository_candidates(self, auto_use: bool = False) -> None:
            try:
                self.repo_candidates = discover_repo_candidates()
                if hasattr(self, "repo_candidate_combo"):
                    self.repo_candidate_combo.configure(values=self.repo_candidates)
                if self.repo_candidates and not self.repo_candidate_var.get():
                    self.repo_candidate_var.set(self.repo_candidates[0])
                if auto_use and self.repo_candidates and not Path(self.repo_source_var.get() or "").exists():
                    self.repo_source_var.set(self.repo_candidates[0])
                    self.use_repo_source_path()
            except Exception as exc:
                self.message_var.set(str(exc))

        def use_selected_repo_candidate(self) -> None:
            if self.repo_candidate_var.get().strip():
                self.repo_source_var.set(self.repo_candidate_var.get().strip())
                self.use_repo_source_path()

        def use_repo_source_path(self) -> None:
            repo_path = self.repo_source_var.get().strip()
            if not repo_path:
                self.message_var.set("Choose a backup repository path first.")
                return
            try:
                response = send_daemon_request({"action": "set_repo_path", "repo_path": repo_path})
                if not response.get("ok"):
                    raise AegisError(response.get("error", "Unknown daemon error"))
                self.repo_path_var.set(repo_path)
                self.message_var.set(response.get("message", "Backup location updated."))
                self.settings_loaded = False
                self.refresh_dashboard()
            except Exception as exc:
                self.message_var.set(str(exc))

        def resolve_disk_path(self, raw_value: str, mapping: Dict[str, str]) -> str:
            value = raw_value.strip()
            return mapping.get(value, value)

        def confirm_dangerous_action(self, title: str, message: str) -> bool:
            return messagebox.askyesno(title, message, icon="warning")

        def create_recovery_usb_from_gui(self) -> None:
            device = self.resolve_disk_path(self.recovery_usb_device_var.get(), self.usb_choice_map)
            if not device:
                self.message_var.set("Choose a recovery USB device first.")
                return
            if not self.confirm_dangerous_action("Create Recovery USB", f"This will erase everything on {device}. Continue?"):
                return
            try:
                response = send_daemon_request({"action": "run_create_recovery_usb", "device": device})
                if not response.get("ok"):
                    raise AegisError(response.get("error", "Unknown daemon error"))
                self.message_var.set(response.get("message", "Recovery USB creation started."))
            except Exception as exc:
                self.message_var.set(str(exc))

        def guided_restore_repo(self) -> None:
            if not self.selected_snapshot_id:
                self.message_var.set("Select a snapshot first.")
                return
            device = self.resolve_disk_path(self.guided_target_disk_var.get(), self.guided_disk_map)
            if not device:
                self.message_var.set("Choose a target disk first.")
                return
            if not self.confirm_dangerous_action("Guided Full Restore", f"This will wipe {device} and restore the selected Full Recovery snapshot. Continue?"):
                return
            try:
                response = send_daemon_request({
                    "action": "run_guided_restore_repo",
                    "snapshot": self.selected_snapshot_id,
                    "target_disk": device,
                    "recovery_password": self.repo_recovery_key_var.get().strip(),
                })
                if not response.get("ok"):
                    raise AegisError(response.get("error", "Unknown daemon error"))
                self.message_var.set(response.get("message", "Guided full restore started."))
            except Exception as exc:
                self.message_var.set(str(exc))

        def guided_restore_bundle(self) -> None:
            device = self.resolve_disk_path(self.guided_target_disk_var.get(), self.guided_disk_map)
            if not device:
                self.message_var.set("Choose a target disk first.")
                return
            bundle_path = self.bundle_file_var.get().strip()
            bundle_url = self.bundle_url_var.get().strip()
            password = self.bundle_password_var.get().strip()
            if not bundle_path and not bundle_url:
                self.message_var.set("Choose a bundle file or enter a hosted URL first.")
                return
            if not password:
                self.message_var.set("Bundle password is required.")
                return
            if not self.confirm_dangerous_action("Guided Full Restore", f"This will wipe {device} and restore the selected Full Recovery bundle. Continue?"):
                return
            try:
                response = send_daemon_request({
                    "action": "run_guided_restore_bundle",
                    "bundle_path": bundle_path,
                    "bundle_url": bundle_url,
                    "password": password,
                    "target_disk": device,
                })
                if not response.get("ok"):
                    raise AegisError(response.get("error", "Unknown daemon error"))
                self.message_var.set(response.get("message", "Guided full restore started."))
            except Exception as exc:
                self.message_var.set(str(exc))

        def daemon_dashboard(self) -> Dict[str, Any]:
            response = send_daemon_request({"action": "dashboard"})
            if not response.get("ok"):
                raise AegisError(response.get("error", "Unknown daemon error"))
            return response["dashboard"]

        def refresh_dashboard(self) -> None:
            try:
                payload = self.daemon_dashboard()
                self.dashboard_payload = payload
                self.populate_dashboard(payload)
            except Exception as exc:
                self.message_var.set(str(exc))

        def periodic_refresh(self) -> None:
            self.refresh_dashboard()
            self.root.after(2000, self.periodic_refresh)

        def populate_dashboard(self, payload: Dict[str, Any]) -> None:
            settings = payload["settings"]
            state = payload["persistent"]
            current_job = payload.get("current_job")
            snapshots = payload.get("snapshots", [])
            warnings = payload.get("warnings", [])
            logs = payload.get("logs", [])

            self.apply_configuration_state(bool(settings.get("onboarding_complete", False)))

            self.status_var.set(
                f"{'Busy: ' + current_job['name'] + ' — ' + current_job['stage'] if current_job else 'Idle'}"
            )

            if current_job:
                if not self.activity_bar_running:
                    self.activity_bar.start(10)
                    self.activity_bar_running = True
            else:
                if self.activity_bar_running:
                    self.activity_bar.stop()
                    self.activity_bar_running = False

            self.summary_labels["machine"].configure(text=f"{settings.get('machine_label')} ({settings.get('machine_id')})")
            self.summary_labels["repo"].configure(text=settings.get("repo_path", ""))
            self.summary_labels["last_good"].configure(text=state.get("last_success_at") or "—")
            self.summary_labels["last_run"].configure(text=state.get("last_run_at") or "—")
            self.summary_labels["last_sync"].configure(text=state.get("last_sync_at") or "—")
            self.summary_labels["recovery_key"].configure(
                text=state.get("recovery_key_path") or "Chosen during encrypted setup; not written to disk."
            )

            self.fill_text(self.warnings_text, "\n".join(warnings) if warnings else "No warnings.")
            self.fill_text(self.logs_text, "\n".join(logs[-100:]) if logs else "No activity yet.")
            self.fill_snapshot_tree(self.backup_tree, snapshots)
            self.fill_snapshot_tree(self.restore_tree, snapshots)
            self.fill_peers_tree(self.peers_tree, settings.get("peers", []))

            if not self.settings_loaded:
                self.fill_peers_tree(self.settings_peers_tree, settings.get("peers", []), settings_mode=True)
                self.machine_label_var.set(settings.get("machine_label", ""))
                self.repo_path_var.set(settings.get("repo_path", ""))
                self.repo_source_var.set(settings.get("repo_path", ""))
                self.encryption_var.set(bool(settings.get("encryption_enabled", True)))
                self.notifications_enabled_var.set(bool(settings.get("notifications_enabled", True)))
                self.default_backup_profile_var.set(settings.get("default_backup_profile", "both"))
                schedule = settings.get("schedule", {})
                self.schedule_enabled_var.set(bool(schedule.get("enabled", False)))
                self.schedule_preset_var.set(schedule.get("preset", "manual"))
                self.schedule_custom_var.set(str(schedule.get("custom_minutes", 60)))
                self.io_yield_var.set(str(settings.get("io_yield_ms", 2)))
                self.apply_packages_var.set(bool(settings.get("apply_packages_on_portable_restore", True)))
                self.peers_enabled_var.set(bool(settings.get("peers_enabled", False)))
                self.fill_text(self.full_excludes_text, "\n".join(settings.get("full_excludes", [])))
                self.fill_text(self.portable_includes_text, "\n".join(settings.get("portable_includes", [])))
                self.fill_text(self.portable_excludes_text, "\n".join(settings.get("portable_excludes", [])))
                self.settings_loaded = True

        def fill_snapshot_tree(self, tree: ttk.Treeview, snapshots: List[Dict[str, Any]]) -> None:
            existing_selection = self.selected_snapshot_id
            for item in tree.get_children():
                tree.delete(item)
            for snap in snapshots:
                values = (
                    snap.get("created_at", ""),
                    snap.get("machine_label", ""),
                    kind_label(snap.get("kind", "")),
                    human_bytes(int(snap.get("archive_bytes", 0))),
                    snap.get("id", ""),
                )
                item_id = tree.insert("", "end", iid=snap.get("id", ""), values=values)
                if snap.get("id") == existing_selection:
                    tree.selection_set(item_id)

        def fill_peers_tree(self, tree: ttk.Treeview, peers: List[Dict[str, Any]], settings_mode: bool = False) -> None:
            for item in tree.get_children():
                tree.delete(item)
            for idx, peer in enumerate(peers):
                if settings_mode:
                    tree.insert("", "end", iid=str(idx), values=(
                        peer.get("label", ""),
                        peer.get("ssh_target", ""),
                        peer.get("repo_path", ""),
                        str(peer.get("port", 22)),
                        peer.get("identity_file", ""),
                        "yes" if peer.get("enabled", True) else "no",
                    ))
                else:
                    tree.insert("", "end", iid=str(idx), values=(
                        "yes" if peer.get("enabled", True) else "no",
                        peer.get("label", ""),
                        peer.get("ssh_target", ""),
                        peer.get("repo_path", ""),
                        str(peer.get("port", 22)),
                    ))

        def fill_text(self, widget: ScrolledText, text: str) -> None:
            widget.delete("1.0", "end")
            widget.insert("1.0", text)

        def on_snapshot_select(self, event) -> None:
            tree = event.widget
            selection = tree.selection()
            if selection:
                self.selected_snapshot_id = selection[0]

        def start_backup(self, profile: str) -> None:
            try:
                response = send_daemon_request({"action": "run_backup", "profile": profile})
                if not response.get("ok"):
                    raise AegisError(response.get("error", "Unknown daemon error"))
                self.message_var.set(response.get("message", "Backup started."))
                self.refresh_dashboard()
            except Exception as exc:
                self.message_var.set(str(exc))

        def start_default_backup(self) -> None:
            profile = self.dashboard_payload.get("settings", {}).get("default_backup_profile", "both")
            self.start_backup(normalize_backup_profile(profile))
        
        def export_selected_bundle(self) -> None:
            if not self.selected_snapshot_id:
                self.message_var.set("Select a snapshot first.")
                return
            password = self.export_password_var.get().strip()
            if not password:
                self.message_var.set("Enter a bundle password first.")
                return
            output = filedialog.asksaveasfilename(defaultextension=".avb", filetypes=[("AegisVault bundle", "*.avb"), ("All files", "*.*")])
            if not output:
                return
            try:
                response = send_daemon_request({
                    "action": "run_export",
                    "snapshot": self.selected_snapshot_id,
                    "output": output,
                    "password": password,
                    "recovery_password": self.export_recovery_key_var.get().strip(),
                })
                if not response.get("ok"):
                    raise AegisError(response.get("error", "Unknown daemon error"))
                self.message_var.set(response.get("message", "Bundle export started."))
            except Exception as exc:
                self.message_var.set(str(exc))

        def delete_selected_snapshot(self) -> None:
            if not self.selected_snapshot_id:
                self.message_var.set("Select a snapshot first.")
                return
            if not self.confirm_dangerous_action(
                "Delete Snapshot",
                f"Delete snapshot {self.selected_snapshot_id}? This removes its manifest and any data chunks no other snapshot still needs.",
            ):
                return
            try:
                response = send_daemon_request({
                    "action": "delete_snapshot",
                    "snapshot": self.selected_snapshot_id,
                })
                if not response.get("ok"):
                    raise AegisError(response.get("error", "Unknown daemon error"))
                self.selected_snapshot_id = ""
                self.message_var.set(response.get("message", "Snapshot deleted."))
                self.refresh_dashboard()
            except Exception as exc:
                self.message_var.set(str(exc))
        
        def restore_repo_snapshot(self) -> None:
            if not self.selected_snapshot_id:
                self.message_var.set("Select a snapshot first.")
                return
            try:
                response = send_daemon_request({
                    "action": "run_restore_repo",
                    "snapshot": self.selected_snapshot_id,
                    "target": self.repo_restore_target_var.get().strip() or "/",
                    "member": self.repo_restore_path_var.get().strip(),
                    "apply_packages": bool(self.apply_packages_var.get()),
                    "recovery_password": self.repo_recovery_key_var.get().strip(),
                })
                if not response.get("ok"):
                    raise AegisError(response.get("error", "Unknown daemon error"))
                self.message_var.set(response.get("message", "Restore started."))
            except Exception as exc:
                self.message_var.set(str(exc))

        def restore_bundle(self) -> None:
            bundle_path = self.bundle_file_var.get().strip()
            bundle_url = self.bundle_url_var.get().strip()
            password = self.bundle_password_var.get().strip()
            if not bundle_path and not bundle_url:
                self.message_var.set("Choose a bundle file or enter a hosted URL.")
                return
            if not password:
                self.message_var.set("Bundle password is required.")
                return
            try:
                response = send_daemon_request({
                    "action": "run_restore_bundle",
                    "bundle_path": bundle_path,
                    "bundle_url": bundle_url,
                    "password": password,
                    "target": self.bundle_restore_target_var.get().strip() or "/",
                    "member": self.bundle_restore_path_var.get().strip(),
                    "apply_packages": bool(self.apply_packages_var.get()),
                })
                if not response.get("ok"):
                    raise AegisError(response.get("error", "Unknown daemon error"))
                self.message_var.set(response.get("message", "Bundle restore started."))
            except Exception as exc:
                self.message_var.set(str(exc))

        def sync_peers_now(self) -> None:
            try:
                response = send_daemon_request({"action": "sync_peers"})
                if not response.get("ok"):
                    raise AegisError(response.get("error", "Unknown daemon error"))
                self.message_var.set(response.get("message", "Peer sync started."))
            except Exception as exc:
                self.message_var.set(str(exc))

        def gather_peer_list(self) -> List[Dict[str, Any]]:
            peers = []
            for iid in self.settings_peers_tree.get_children():
                values = self.settings_peers_tree.item(iid, "values")
                peers.append({
                    "label": values[0],
                    "ssh_target": values[1],
                    "repo_path": values[2],
                    "port": int(values[3] or 22),
                    "enabled": values[5] == "yes",
                    "identity_file": values[4],
                })
            return peers

        def add_peer_from_form(self) -> None:
            label = self.peer_label_var.get().strip()
            target = self.peer_target_var.get().strip()
            repo_path = self.peer_repo_var.get().strip() or DEFAULT_REPO
            port = self.peer_port_var.get().strip() or "22"
            identity = self.peer_identity_var.get().strip()
            if not target:
                self.message_var.set("Peer SSH target is required.")
                return
            selected = self.settings_peers_tree.selection()
            values = (label, target, repo_path, port, identity, "yes")
            if selected:
                self.settings_peers_tree.item(selected[0], values=values)
            else:
                self.settings_peers_tree.insert("", "end", values=values)
            self.peer_label_var.set("")
            self.peer_target_var.set("")
            self.peer_repo_var.set(DEFAULT_REPO)
            self.peer_port_var.set("22")
            self.peer_identity_var.set(identity)
            self.message_var.set("Peer staged. Save settings to persist it.")

        def remove_selected_peer(self) -> None:
            for item in self.settings_peers_tree.selection():
                self.settings_peers_tree.delete(item)
            self.message_var.set("Selected peer removed from staged settings. Save settings to persist.")

        def on_peer_select(self, event) -> None:
            selection = self.settings_peers_tree.selection()
            if not selection:
                return
            values = self.settings_peers_tree.item(selection[0], "values")
            self.peer_label_var.set(values[0])
            self.peer_target_var.set(values[1])
            self.peer_repo_var.set(values[2])
            self.peer_port_var.set(values[3])
            self.peer_identity_var.set(values[4])

        def build_settings_payload(self, onboarding_complete: bool = True) -> Dict[str, Any]:
            full_excludes = split_lines(self.full_excludes_text.get("1.0", "end"))
            portable_includes = split_lines(self.portable_includes_text.get("1.0", "end"))
            portable_excludes = split_lines(self.portable_excludes_text.get("1.0", "end"))

            peers = []
            for iid in self.settings_peers_tree.get_children():
                values = self.settings_peers_tree.item(iid, "values")
                peers.append({
                    "enabled": values[5] == "yes",
                    "label": values[0],
                    "ssh_target": values[1],
                    "repo_path": values[2],
                    "port": int(values[3] or 22),
                    "identity_file": values[4],
                })

            schedule_enabled = bool(self.schedule_enabled_var.get())
            schedule_preset = self.schedule_preset_var.get().strip() or ("daily" if schedule_enabled else "manual")
            if not schedule_enabled:
                schedule_preset = "manual"

            return {
                "version": 2,
                "onboarding_complete": onboarding_complete,
                "machine_id": self.dashboard_payload.get("settings", {}).get("machine_id", machine_id()),
                "machine_label": self.machine_label_var.get().strip() or hostname(),
                "repo_path": self.repo_path_var.get().strip() or DEFAULT_REPO,
                "encryption_enabled": bool(self.encryption_var.get()),
                "notifications_enabled": bool(self.notifications_enabled_var.get()),
                "default_backup_profile": normalize_backup_profile(self.default_backup_profile_var.get().strip() or "both"),
                "schedule": {
                    "enabled": schedule_enabled,
                    "preset": schedule_preset,
                    "custom_minutes": int(self.schedule_custom_var.get().strip() or "60"),
                },
                "chunk_size_mib": self.dashboard_payload.get("settings", {}).get("chunk_size_mib", DEFAULT_CHUNK_MIB),
                "io_yield_ms": int(self.io_yield_var.get().strip() or "2"),
                "apply_packages_on_portable_restore": bool(self.apply_packages_var.get()),
                "full_excludes": full_excludes,
                "portable_includes": portable_includes,
                "portable_excludes": portable_excludes,
                "peers_enabled": bool(self.peers_enabled_var.get()),
                "peers": peers,
            }
        
        def save_settings(self) -> None:
            try:
                payload = self.build_settings_payload(onboarding_complete=True)
                response = self.submit_settings_with_recovery_password_if_needed(payload)
                self.message_var.set(response.get("message", "Settings saved."))
                self.settings_loaded = False
                self.refresh_dashboard()
            except Exception as exc:
                self.message_var.set(str(exc))

    root = tk.Tk()
    app = App(root)
    root.mainloop()
    return 0


def list_snapshots_command() -> int:
    try:
        data = dashboard()
        for snap in data.snapshots:
            print(f"{snap['created_at']}  {snap['machine_label']}  {snap['kind']}  {snap['id']}")
        return 0
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="aegisvault", description="Encrypted Linux backup, restore, and peer sync in one compact app.")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("gui")
    sub.add_parser("daemon")
    init_parser = sub.add_parser("init")
    init_parser.add_argument("--repo")
    init_parser.add_argument("--label")
    init_parser.add_argument("--encryption", choices=["on", "off"], default="on")
    init_parser.add_argument("--recovery-password")

    sub.add_parser("status")
    sub.add_parser("dashboard")
    sub.add_parser("list-snapshots")
    sub.add_parser("list-disks")

    backup = sub.add_parser("backup-now")
    backup.add_argument("--profile", choices=["full_recovery", "portable_state", "both"], default="both")
    backup.add_argument("--direct", action="store_true")

    export = sub.add_parser("export-bundle")
    export.add_argument("snapshot")
    export.add_argument("output")
    export.add_argument("--password", required=True)
    export.add_argument("--recovery-password")
    export.add_argument("--direct", action="store_true")

    restore = sub.add_parser("restore")
    restore.add_argument("--snapshot")
    restore.add_argument("--bundle")
    restore.add_argument("--url")
    restore.add_argument("--target", default="/")
    restore.add_argument("--target-disk")
    restore.add_argument("--guided", action="store_true")
    restore.add_argument("--path")
    restore.add_argument("--apply-packages", action="store_true")
    restore.add_argument("--recovery-password")
    restore.add_argument("--bundle-password")
    restore.add_argument("--direct", action="store_true")

    recovery = sub.add_parser("create-recovery-usb")
    recovery.add_argument("--device", required=True)
    recovery.add_argument("--direct", action="store_true")

    auth = sub.add_parser("authorize-socket")
    auth.add_argument("--user", required=True)

    sync = sub.add_parser("sync-peers")
    sync.add_argument("--direct", action="store_true")

    return parser.parse_args(argv)


def main(argv: List[str]) -> int:
    args = parse_args(argv)
    cmd = args.command or "gui"
    try:
        if cmd == "gui":
            return gui_main()
        if cmd == "daemon":
            return daemon_main()
        if cmd == "init":
            return init_command(args.repo, args.label, args.encryption == "on", args.recovery_password)
        if cmd in ("status", "dashboard"):
            return print_status_json()
        if cmd == "list-snapshots":
            return list_snapshots_command()
        if cmd == "list-disks":
            return list_disks_command()
        if cmd == "backup-now":
            return backup_now_command(args.profile, args.direct)
        if cmd == "export-bundle":
            return export_bundle_command(args.snapshot, args.output, args.password, args.recovery_password, args.direct)
        if cmd == "restore":
            return restore_command(args)
        if cmd == "create-recovery-usb":
            return create_recovery_usb_command(args.device, args.direct)
        if cmd == "authorize-socket":
            return authorize_socket_command(args.user)
        if cmd == "sync-peers":
            return sync_peers_command(args.direct)
        raise AegisError(f"Unknown command: {cmd}")
    except AegisError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

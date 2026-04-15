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


APP_NAME = "AegisVault"
SOCKET_PATH = "/run/aegisvault/daemon.sock"
VAR_DIR = Path("/var/lib/aegisvault")
CONFIG_PATH = VAR_DIR / "settings.json"
STATE_PATH = VAR_DIR / "state.json"
KEY_DIR = VAR_DIR / "keys"
LOCK_PATH = VAR_DIR / "backup.lock"
BUNDLE_MAGIC = b"AGBND1"
OBJECT_MAGIC = b"AGOBJ1"
DEFAULT_REPO = "/var/backups/aegisvault"
DEFAULT_CHUNK_MIB = 4
BUFFER_SIZE = 1024 * 1024
LOG_LIMIT = 250
RECOVERY_MARKER = Path("/etc/aegisvault-recovery")
RECOVERY_MOUNT_ROOT = Path("/mnt/aegisvault-recovery")
AUTO_MOUNT_ROOT = Path("/media/aegisvault")
DEFAULT_RECOVERY_SUITE = "bookworm"
DEFAULT_RECOVERY_MIRROR = "https://deb.debian.org/debian"
DEFAULT_REPO_SLUG = "MagnetosphereLabs/Aegis"
MIN_RECOVERY_USB_BYTES = 8 * 1024 * 1024 * 1024


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
    version: int = 1
    machine_id: str = ""
    machine_label: str = ""
    repo_path: str = DEFAULT_REPO
    encryption_enabled: bool = True
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
    return KEY_DIR / f"{machine}.key"


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
        version=int(data.get("version", 1)),
        machine_id=str(data.get("machine_id") or machine_id()),
        machine_label=str(data.get("machine_label") or hostname()),
        repo_path=str(data.get("repo_path") or DEFAULT_REPO),
        encryption_enabled=bool(data.get("encryption_enabled", True)),
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
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        check=check,
        capture_output=capture,
        text=True,
    )


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
        "NAME,PATH,TYPE,SIZE,RM,RO,TRAN,MODEL,SERIAL,FSTYPE,LABEL,UUID,PARTUUID,PKNAME,MOUNTPOINTS",
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
            "mountpoints": mountpoints,
        }
        out.append(entry)
        for child in node.get("children") or []:
            walk(child)

    for node in payload.get("blockdevices") or []:
        walk(node)
    return out


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
        "dosfstools",
        "gdisk",
        "grub-pc-bin",
        "grub-efi-amd64-bin",
        "ca-certificates",
    ])


def assert_safe_target_disk(device: str) -> None:
    if run_command_optional(["lsblk", "-ndo", "TYPE", device]).strip() != "disk":
        raise AegisError(f"Choose a whole-disk device like /dev/sdb, not {device}.")
    if device == current_root_disk():
        raise AegisError("Refusing to operate on the disk hosting the currently booted system.")


def recovery_key_normalized(key: str) -> str:
    return "".join(ch for ch in key.upper() if ch.isalnum())


def generate_recovery_key() -> str:
    raw = base64.b16encode(os.urandom(20)).decode("ascii")
    return "-".join(raw[i:i+4] for i in range(0, len(raw), 4))


def derive_key_from_password(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(password.encode("utf-8"))


def wrap_machine_key(machine: str, machine_key: bytes, recovery_key: str) -> Dict[str, Any]:
    salt = os.urandom(16)
    key = derive_key_from_password(recovery_key_normalized(recovery_key), salt)
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


def unwrap_machine_key(envelope: Dict[str, Any], recovery_key: str) -> bytes:
    salt = base64.b64decode(envelope["salt_b64"])
    nonce = base64.b64decode(envelope["nonce_b64"])
    ciphertext = base64.b64decode(envelope["ciphertext_b64"])
    key = derive_key_from_password(recovery_key_normalized(recovery_key), salt)
    cipher = AESGCM(key)
    return cipher.decrypt(nonce, ciphertext, None)


def materialize_settings(settings: Settings) -> Optional[str]:
    Path(settings.repo_path).mkdir(parents=True, exist_ok=True)
    repo = Path(settings.repo_path)
    (repo_machine_dir(repo, settings.machine_id) / "snapshots").mkdir(parents=True, exist_ok=True)
    (repo / "objects" / settings.machine_id).mkdir(parents=True, exist_ok=True)
    VAR_DIR.mkdir(parents=True, exist_ok=True)
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    if not settings.encryption_enabled:
        return None
    local_key = local_key_path(settings.machine_id)
    envelope_path = key_envelope_path(repo, settings.machine_id)
    if local_key.exists() and envelope_path.exists():
        return None
    machine_key_value = os.urandom(32)
    atomic_write(local_key, machine_key_value, mode=0o600)
    os.chmod(local_key, 0o600)
    recovery_key = generate_recovery_key()
    envelope = wrap_machine_key(settings.machine_id, machine_key_value, recovery_key)
    save_json(envelope_path, envelope, mode=0o600)
    recovery_file = VAR_DIR / f"RECOVERY-KEY-{short_machine(settings.machine_id)}.txt"
    recovery_text = "\n".join([
        f"{APP_NAME} recovery key",
        "",
        f"Machine label: {settings.machine_label}",
        f"Machine ID: {settings.machine_id}",
        f"Repository: {settings.repo_path}",
        "",
        f"Recovery key: {recovery_key}",
        "",
        "This key can decrypt this machine's repository encryption key on another system.",
        "Store it somewhere safe and separate from the machine itself.",
        "",
    ])
    atomic_write(recovery_file, recovery_text.encode("utf-8"), mode=0o600)
    state = load_state()
    state.recovery_key_path = str(recovery_file)
    save_state(state)
    return str(recovery_file)


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
    return "Full Recovery" if kind == "full_recovery" else "Portable System State"


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
    key_path = local_key_path(machine)
    if not key_path.exists():
        raise AegisError(f"Local machine key is missing for {machine}.")
    return key_path.read_bytes()


def load_key_envelope(repo: Path, machine: str) -> Dict[str, Any]:
    path = key_envelope_path(repo, machine)
    if not path.exists():
        raise AegisError(f"Key envelope is missing for {machine}.")
    return load_json(path)


def resolve_machine_key_for_manifest(settings: Settings, manifest: SnapshotManifest, recovery_key: Optional[str]) -> Optional[bytes]:
    repo = Path(settings.repo_path)
    objects_root = repo / "objects" / manifest.machine_id
    if not objects_root.exists():
        return None
    local_key = local_key_path(manifest.machine_id)
    if local_key.exists():
        return local_key.read_bytes()
    if recovery_key:
        envelope = load_key_envelope(repo, manifest.machine_id)
        return unwrap_machine_key(envelope, recovery_key)
    raise AegisError(
        f"No local key found for machine {manifest.machine_id}. Supply that machine's recovery key."
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
        state.last_run_at = now_rfc3339()
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


def restore_snapshot_from_repo(settings: Settings, snapshot_id: str, target: Path, member: Optional[str], apply_packages: bool, recovery_key: Optional[str]) -> None:
    manifest = find_snapshot_manifest(Path(settings.repo_path), snapshot_id)
    if manifest.kind == "full_recovery" and target.resolve() == Path("/"):
        raise AegisError("Full Recovery restore must target an offline-mounted root, not /.")
    key = resolve_machine_key_for_manifest(settings, manifest, recovery_key)
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
    mounts: List[str] = []
    pairs = [("/dev", target / "dev"), ("/proc", target / "proc"), ("/sys", target / "sys"), ("/run", target / "run")]
    try:
        for source, dest in pairs:
            dest.mkdir(parents=True, exist_ok=True)
            subprocess.run(["mount", "--bind", source, str(dest)], check=False, capture_output=True)
            mounts.append(str(dest))
        yield
    finally:
        for mount_path in reversed(mounts):
            subprocess.run(["umount", "-lf", mount_path], check=False, capture_output=True)


def run_chroot(target: Path, args: List[str]) -> subprocess.CompletedProcess:
    return subprocess.run(["chroot", str(target), *args], check=False, capture_output=True, text=True)


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


def guided_partition_disk(device: str) -> Dict[str, str]:
    assert_safe_target_disk(device)
    ensure_recovery_builder_prereqs()
    unmount_device_tree(device)
    subprocess.run(["swapoff", "-a"], check=False, capture_output=True)
    run_command(["sgdisk", "--zap-all", device], check=False, capture=True)
    run_command(["wipefs", "-a", device], check=False, capture=True)
    run_command(["parted", "-s", device, "mklabel", "gpt"], check=True, capture=True)
    run_command(["parted", "-s", device, "mkpart", "bios_grub", "1MiB", "3MiB"], check=True, capture=True)
    run_command(["parted", "-s", device, "set", "1", "bios_grub", "on"], check=True, capture=True)
    run_command(["parted", "-s", device, "mkpart", "ESP", "fat32", "3MiB", "1027MiB"], check=True, capture=True)
    run_command(["parted", "-s", device, "set", "2", "esp", "on"], check=True, capture=True)
    run_command(["parted", "-s", device, "mkpart", "root", "ext4", "1027MiB", "100%"], check=True, capture=True)
    subprocess.run(["partprobe", device], check=False, capture_output=True)
    subprocess.run(["udevadm", "settle"], check=False, capture_output=True)
    bios_partition = disk_partition_path(device, 1)
    efi_partition = disk_partition_path(device, 2)
    root_partition = disk_partition_path(device, 3)
    wait_for_partition_device(efi_partition)
    wait_for_partition_device(root_partition)
    run_command(["mkfs.vfat", "-F", "32", "-n", "AEGIS-EFI", efi_partition], check=True, capture=True)
    run_command(["mkfs.ext4", "-F", "-L", "AegisSystem", root_partition], check=True, capture=True)
    return {"disk": device, "bios": bios_partition, "efi": efi_partition, "root": root_partition}


@contextmanager
def mounted_guided_target(device: str):
    layout = guided_partition_disk(device)
    mount_root = Path(tempfile.mkdtemp(prefix="aegisvault-target-"))
    try:
        run_command(["mount", layout["root"], str(mount_root)], check=True, capture=True)
        (mount_root / "boot/efi").mkdir(parents=True, exist_ok=True)
        run_command(["mount", layout["efi"], str(mount_root / "boot/efi")], check=True, capture=True)
        yield layout, mount_root
    finally:
        subprocess.run(["umount", "-lf", str(mount_root / "boot/efi")], check=False, capture_output=True)
        subprocess.run(["umount", "-lf", str(mount_root)], check=False, capture_output=True)
        shutil.rmtree(mount_root, ignore_errors=True)


def guided_full_restore_from_repo(settings: Settings, snapshot_id: str, target_disk: str, recovery_key: Optional[str]) -> None:
    manifest = find_snapshot_manifest(Path(settings.repo_path), snapshot_id)
    if manifest.kind != "full_recovery":
        raise AegisError("Guided full restore only works with Full Recovery snapshots.")
    key = resolve_machine_key_for_manifest(settings, manifest, recovery_key)
    with mounted_guided_target(target_disk) as (layout, mount_root):
        update_stage(f"Restoring {snapshot_id} to {target_disk}")
        extract_manifest_from_repo_to_target(Path(settings.repo_path), manifest, key, mount_root, None)
        write_guided_restore_fstab(mount_root, layout["root"], layout["efi"])
        best_effort_full_restore_post_actions(mount_root, layout["disk"])


def bundle_manifest_and_archive(bundle_path: Path, password: str) -> Tuple[SnapshotManifest, Path, tempfile.TemporaryDirectory]:
    if not password.strip():
        raise AegisError("Bundle password is required.")
    plain_bundle = tempfile.NamedTemporaryFile(delete=False)
    plain_bundle_path = Path(plain_bundle.name)
    plain_bundle.close()
    try:
        with bundle_path.open("rb") as src, plain_bundle_path.open("wb") as dst:
            decrypt_bundle_to_stream(src, password, dst)
        td = tempfile.TemporaryDirectory()
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
    assert_safe_target_disk(device)
    disks = {d["path"]: d for d in list_disk_choices()}
    size = int(disks.get(device, {}).get("size") or 0)
    if size and size < MIN_RECOVERY_USB_BYTES:
        raise AegisError("Recovery USB target is too small. Use at least 8 GB.")
    ensure_recovery_builder_prereqs()
    update_stage("Preparing recovery USB partitions")
    with mounted_guided_target(device) as (layout, mount_root):
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
        with mounted_chroot_bindings(mount_root):
            update_stage("Installing recovery environment packages")
            run_chroot_checked(mount_root, ["/usr/bin/env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "update"], "apt-get update in recovery media")
            packages = [
                "linux-image-amd64", "systemd-sysv", "grub-pc", "grub-efi-amd64",
                "python3", "python3-tk", "python3-cryptography",
                "xorg", "xinit", "openbox", "xterm", "dbus-x11",
                "network-manager", "ca-certificates", "curl", "rsync", "openssh-client", "tar",
                "parted", "dosfstools", "e2fsprogs", "btrfs-progs", "xfsprogs", "ntfs-3g", "exfatprogs",
                "util-linux", "sudo"
            ]
            run_chroot_checked(mount_root, ["/usr/bin/env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y", *packages], "package install in recovery media")

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


def export_bundle_from_repo(settings: Settings, snapshot_id: str, output: Path, password: str, recovery_key: Optional[str]) -> None:
    if not password.strip():
        raise AegisError("Bundle export requires a password.")
    manifest = find_snapshot_manifest(Path(settings.repo_path), snapshot_id)
    key = resolve_machine_key_for_manifest(settings, manifest, recovery_key)
    with tempfile.NamedTemporaryFile(delete=False) as archive_tmp:
        archive_tmp_path = Path(archive_tmp.name)
        digest = stream_archive_from_repo(Path(settings.repo_path), manifest, key, archive_tmp)
    if digest != manifest.archive_sha256:
        archive_tmp_path.unlink(missing_ok=True)
        raise AegisError("Archive integrity mismatch while exporting bundle.")
    with tempfile.NamedTemporaryFile(delete=False) as plain_bundle:
        plain_bundle_path = Path(plain_bundle.name)
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
        warnings.append(f"Repository path is not present: {settings.repo_path}")
    if settings.encryption_enabled and not local_key_path(settings.machine_id).exists():
        warnings.append("Encryption is enabled but the local machine key file is missing.")
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

    def worker():
        try:
            func()
        except Exception as exc:
            state = load_state()
            state.last_error = f"{exc}"
            save_state(state)
            log_line(f"{name} failed: {exc}")
            log_line(traceback.format_exc())
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
        recovery_path = materialize_settings(settings)
        save_settings(settings)
        state = load_state()
        if recovery_path:
            state.recovery_key_path = recovery_path
            save_state(state)
            return {"ok": True, "message": f"Settings saved. Recovery key written to {recovery_path}."}
        return {"ok": True, "message": "Settings saved."}
    if action == "run_backup":
        profile = request.get("profile", "both")
        run_job(f"Backup ({profile})", lambda: perform_backup(load_settings(), profile))
        return {"ok": True, "message": "Backup started."}
    if action == "run_export":
        snapshot_id = request["snapshot"]
        output = Path(request["output"])
        password = request["password"]
        recovery_key = request.get("recovery_key") or None
        run_job(
            f"Export bundle {snapshot_id}",
            lambda: export_bundle_from_repo(load_settings(), snapshot_id, output, password, recovery_key),
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
                request.get("recovery_key") or None,
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
    if action == "set_repo_path":
        repo_path = str(request.get("repo_path") or "").strip()
        if not repo_path:
            raise AegisError("Repository path is required.")
        settings = load_settings()
        settings.repo_path = repo_path
        if not settings.full_excludes:
            settings.full_excludes = default_full_excludes(settings.repo_path)
        save_settings(settings)
        return {"ok": True, "message": f"Repository path set to {repo_path}."}
    if action == "run_create_recovery_usb":
        device = str(request.get("device") or "").strip()
        if not device:
            raise AegisError("Choose a target USB disk first.")
        run_job(f"Create recovery USB on {device}", lambda: create_recovery_usb(device))
        return {"ok": True, "message": "Recovery USB creation started."}
    if action == "run_guided_restore_repo":
        device = str(request.get("target_disk") or "").strip()
        snapshot_id = str(request.get("snapshot") or "").strip()
        recovery_key = request.get("recovery_key") or None
        if not snapshot_id or not device:
            raise AegisError("Snapshot and target disk are required.")
        run_job(f"Guided restore {snapshot_id} to {device}", lambda: guided_full_restore_from_repo(load_settings(), snapshot_id, device, recovery_key))
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
            if not schedule_due(settings, state):
                continue
            with RUNTIME.lock:
                if RUNTIME.current_job is not None:
                    continue
            run_job("Scheduled backup", lambda: perform_backup(load_settings(), "both"))
        except Exception as exc:
            log_line(f"Scheduler error: {exc}")


def daemon_main() -> int:
    ensure_root()
    VAR_DIR.mkdir(parents=True, exist_ok=True)
    KEY_DIR.mkdir(parents=True, exist_ok=True)
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

        subprocess.run(["systemctl", "start", "aegisvault.service"], check=False, capture_output=True)

        deadline = time.time() + 5
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


def init_command(repo: Optional[str], label: Optional[str], encryption: bool) -> int:
    ensure_root()
    settings = load_settings()
    if repo:
        settings.repo_path = repo
        settings.full_excludes = default_full_excludes(settings.repo_path)
    if label:
        settings.machine_label = label
    settings.encryption_enabled = encryption
    if not settings.machine_id:
        settings.machine_id = machine_id()
    if not settings.machine_label:
        settings.machine_label = hostname()
    settings.portable_includes = settings.portable_includes or default_portable_includes()
    settings.portable_excludes = settings.portable_excludes or default_portable_excludes()
    recovery_path = materialize_settings(settings)
    save_settings(settings)
    print(f"{APP_NAME} initialized at {settings.repo_path}")
    if recovery_path:
        print(f"Recovery key written to {recovery_path}")
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


def export_bundle_command(snapshot: str, output: str, password: str, recovery_key: Optional[str], direct: bool) -> int:
    try:
        if not direct:
            try:
                response = send_daemon_request({
                    "action": "run_export",
                    "snapshot": snapshot,
                    "output": output,
                    "password": password,
                    "recovery_key": recovery_key or "",
                })
                if not response.get("ok"):
                    raise AegisError(response.get("error", "Unknown daemon error"))
                print(response["message"])
                return 0
            except Exception:
                pass
        ensure_root()
        export_bundle_from_repo(load_settings(), snapshot, Path(output), password, recovery_key)
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
                            "recovery_key": args.recovery_key or "",
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
                        "recovery_key": args.recovery_key or "",
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
                guided_full_restore_from_repo(settings, args.snapshot, target_disk, args.recovery_key)
            elif args.bundle:
                guided_full_restore_from_bundle(Path(args.bundle), args.bundle_password or "", target_disk)
            elif args.url:
                guided_full_restore_from_bundle_url(args.url, args.bundle_password or "", target_disk)
            else:
                raise AegisError("Provide --snapshot, --bundle, or --url.")
        else:
            target = Path(args.target)
            if args.snapshot:
                restore_snapshot_from_repo(settings, args.snapshot, target, args.path, bool(args.apply_packages), args.recovery_key)
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
    from tkinter import filedialog, messagebox, ttk
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
            self.repo_candidates: List[str] = []
            self.usb_choice_map: Dict[str, str] = {}
            self.guided_disk_map: Dict[str, str] = {}
            self.recovery_mounts: List[str] = []

            self.build_ui()
            if self.recovery_mode and os.geteuid() == 0:
                try:
                    self.recovery_mounts = auto_mount_recovery_sources()
                except Exception:
                    self.recovery_mounts = []
            self.refresh_local_device_lists()
            self.scan_repository_candidates(auto_use=True)
            if self.recovery_mode:
                self.notebook.select(self.restore_tab)
                hint = "Recovery mode: use Guided Full Restore for the easiest same-machine disaster restore."
                if self.recovery_mounts:
                    hint += f" Mounted source volumes: {', '.join(self.recovery_mounts)}."
                self.message_var.set(hint)
            self.refresh_dashboard()
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

        def build_overview_tab(self) -> None:
            summary = ttk.Frame(self.overview_tab)
            summary.pack(fill="x")
            self.summary_labels: Dict[str, ttk.Label] = {}
            grid_items = [
                ("machine", "Machine"),
                ("repo", "Repository"),
                ("last_good", "Last good backup"),
                ("last_run", "Last attempted backup"),
                ("last_sync", "Last peer sync"),
                ("recovery_key", "Recovery key file"),
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
                ("repo", "Repository"),
                ("last_good", "Last good backup"),
                ("last_run", "Last attempted backup"),
                ("last_sync", "Last peer sync"),
                ("recovery_key", "Recovery key file"),
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
            tree.heading("bytes", text="Bytes")
            tree.heading("id", text="Snapshot ID")
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
            ttk.Label(controls, text="Create snapshots", style="Header.TLabel").grid(row=0, column=0, sticky="w")
            ttk.Button(controls, text="Back Up Both", command=lambda: self.start_backup("both")).grid(row=1, column=0, padx=(0, 8), pady=(10, 0), sticky="w")
            ttk.Button(controls, text="Back Up Full Recovery", command=lambda: self.start_backup("full_recovery")).grid(row=1, column=1, padx=(0, 8), pady=(10, 0), sticky="w")
            ttk.Button(controls, text="Back Up Portable System State", command=lambda: self.start_backup("portable_state")).grid(row=1, column=2, padx=(0, 8), pady=(10, 0), sticky="w")

            snaps = ttk.Frame(self.backup_tab)
            snaps.pack(fill="both", expand=True, pady=(18, 0))
            ttk.Label(snaps, text="Available snapshots", style="Header.TLabel").pack(anchor="w")
            self.backup_tree = self.build_snapshot_table(snaps)
            self.backup_tree.pack(fill="both", expand=True, pady=(8, 0))

            export = ttk.Frame(self.backup_tab)
            export.pack(fill="x", pady=(18, 0))
            ttk.Label(export, text="Export selected snapshot to encrypted single file", style="Header.TLabel").grid(row=0, column=0, columnspan=3, sticky="w")
            ttk.Label(export, text="Bundle password").grid(row=1, column=0, sticky="w", pady=(10, 0))
            ttk.Entry(export, textvariable=self.export_password_var, show="*", width=34).grid(row=1, column=1, sticky="w", pady=(10, 0))
            ttk.Label(export, text="Recovery key for foreign machine snapshot (optional)").grid(row=2, column=0, sticky="w", pady=(10, 0))
            ttk.Entry(export, textvariable=self.export_recovery_key_var, width=34).grid(row=2, column=1, sticky="w", pady=(10, 0))
            ttk.Button(export, text="Choose Output and Export", command=self.export_selected_bundle).grid(row=2, column=2, padx=(12, 0), pady=(10, 0), sticky="w")

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
            ttk.Label(intro, text="Backup repository source").grid(row=2, column=0, sticky="w", pady=(12, 0))
            ttk.Entry(intro, textvariable=self.repo_source_var, width=58).grid(row=2, column=1, sticky="w", pady=(12, 0))
            ttk.Button(intro, text="Browse", command=lambda: self.browse_directory(self.repo_source_var)).grid(row=2, column=2, padx=(8, 0), pady=(12, 0))
            ttk.Button(intro, text="Use This Repo", command=self.use_repo_source_path).grid(row=2, column=3, padx=(8, 0), pady=(12, 0))
            ttk.Button(intro, text="Scan Mounted Disks", command=lambda: self.scan_repository_candidates(auto_use=False)).grid(row=2, column=4, padx=(8, 0), pady=(12, 0))
            ttk.Label(intro, text="Discovered repos").grid(row=3, column=0, sticky="w", pady=(10, 0))
            self.repo_candidate_combo = ttk.Combobox(intro, textvariable=self.repo_candidate_var, width=56, state="readonly")
            self.repo_candidate_combo.grid(row=3, column=1, sticky="w", pady=(10, 0))
            ttk.Button(intro, text="Use Selected", command=self.use_selected_repo_candidate).grid(row=3, column=2, padx=(8, 0), pady=(10, 0))

            ttk.Separator(self.restore_tab, orient="horizontal").pack(fill="x", pady=18)

            helper = ttk.Frame(self.restore_tab)
            helper.pack(fill="x")
            if self.recovery_mode:
                ttk.Label(helper, text="Guided Full Restore (recommended)", style="Header.TLabel").grid(row=0, column=0, columnspan=4, sticky="w")
                ttk.Label(helper, text="Select the destination disk. AegisVault will wipe it, recreate a bootable layout, restore the Full Recovery snapshot, refresh initramfs, and reinstall the bootloader.", wraplength=1080, style="Muted.TLabel").grid(row=1, column=0, columnspan=4, sticky="w", pady=(6, 0))
                ttk.Label(helper, text="Target disk").grid(row=2, column=0, sticky="w", pady=(12, 0))
                self.guided_disk_combo = ttk.Combobox(helper, textvariable=self.guided_target_disk_var, width=70, state="readonly")
                self.guided_disk_combo.grid(row=2, column=1, sticky="w", pady=(12, 0))
                ttk.Button(helper, text="Refresh Drives", command=self.refresh_local_device_lists).grid(row=2, column=2, padx=(8, 0), pady=(12, 0))
                ttk.Button(helper, text="Restore Selected Snapshot to Disk", command=self.guided_restore_repo).grid(row=3, column=1, sticky="w", pady=(12, 0))
                ttk.Button(helper, text="Restore Bundle or URL to Disk", command=self.guided_restore_bundle).grid(row=3, column=2, sticky="w", padx=(8, 0), pady=(12, 0))
            else:
                ttk.Label(helper, text="Create Recovery USB for Full Recovery snapshots", style="Header.TLabel").grid(row=0, column=0, columnspan=4, sticky="w")
                ttk.Label(helper, text="Plug in an empty 8–16 GB USB drive. AegisVault will build a bootable Debian-based recovery environment that starts straight into the restore UI so a casual user can click through a full-machine restore.", wraplength=1080, style="Muted.TLabel").grid(row=1, column=0, columnspan=4, sticky="w", pady=(6, 0))
                ttk.Label(helper, text="Recovery USB device").grid(row=2, column=0, sticky="w", pady=(12, 0))
                self.recovery_usb_combo = ttk.Combobox(helper, textvariable=self.recovery_usb_device_var, width=70, state="readonly")
                self.recovery_usb_combo.grid(row=2, column=1, sticky="w", pady=(12, 0))
                ttk.Button(helper, text="Refresh Drives", command=self.refresh_local_device_lists).grid(row=2, column=2, padx=(8, 0), pady=(12, 0))
                ttk.Button(helper, text="Create Recovery USB", command=self.create_recovery_usb_from_gui).grid(row=3, column=1, sticky="w", pady=(12, 0))

            ttk.Separator(self.restore_tab, orient="horizontal").pack(fill="x", pady=18)

            repo_section = ttk.Frame(self.restore_tab)
            repo_section.pack(fill="x")
            ttk.Label(repo_section, text="Manual restore from repository snapshot", style="Header.TLabel").grid(row=0, column=0, columnspan=4, sticky="w")
            self.restore_tree = self.build_snapshot_table(repo_section)
            self.restore_tree.grid(row=1, column=0, columnspan=4, sticky="nsew", pady=(8, 0))
            repo_section.grid_columnconfigure(0, weight=1)
            repo_section.grid_rowconfigure(1, weight=1)

            ttk.Label(repo_section, text="Target path").grid(row=2, column=0, sticky="w", pady=(12, 0))
            ttk.Entry(repo_section, textvariable=self.repo_restore_target_var, width=46).grid(row=2, column=1, sticky="w", pady=(12, 0))
            ttk.Button(repo_section, text="Browse", command=lambda: self.browse_directory(self.repo_restore_target_var)).grid(row=2, column=2, padx=(8, 0), pady=(12, 0))
            ttk.Label(repo_section, text="Selective path inside snapshot").grid(row=3, column=0, sticky="w", pady=(12, 0))
            ttk.Entry(repo_section, textvariable=self.repo_restore_path_var, width=46).grid(row=3, column=1, sticky="w", pady=(12, 0))
            ttk.Label(repo_section, text="Recovery key (only needed for other machine snapshots)").grid(row=4, column=0, sticky="w", pady=(12, 0))
            ttk.Entry(repo_section, textvariable=self.repo_recovery_key_var, width=46).grid(row=4, column=1, sticky="w", pady=(12, 0))
            ttk.Button(repo_section, text="Restore Selected Snapshot", command=self.restore_repo_snapshot).grid(row=4, column=2, padx=(8, 0), pady=(12, 0))

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
            ttk.Label(general, text="General", style="Header.TLabel").grid(row=0, column=0, columnspan=3, sticky="w")
            ttk.Label(general, text="Machine label").grid(row=1, column=0, sticky="w", pady=(10, 0))
            ttk.Entry(general, textvariable=self.machine_label_var, width=40).grid(row=1, column=1, sticky="w", pady=(10, 0))
            ttk.Label(general, text="Repository path").grid(row=2, column=0, sticky="w", pady=(10, 0))
            ttk.Entry(general, textvariable=self.repo_path_var, width=40).grid(row=2, column=1, sticky="w", pady=(10, 0))
            ttk.Button(general, text="Browse", command=lambda: self.browse_directory(self.repo_path_var)).grid(row=2, column=2, padx=(8, 0), pady=(10, 0))
            ttk.Checkbutton(general, text="Encrypt repository storage", variable=self.encryption_var).grid(row=3, column=0, columnspan=2, sticky="w", pady=(10, 0))
            ttk.Checkbutton(general, text="Apply package list after portable restore to /", variable=self.apply_packages_var).grid(row=4, column=0, columnspan=2, sticky="w", pady=(10, 0))

            schedule = ttk.Frame(left)
            schedule.pack(fill="x", pady=(24, 0))
            ttk.Label(schedule, text="Scheduling and smoothing", style="Header.TLabel").grid(row=0, column=0, columnspan=3, sticky="w")
            ttk.Checkbutton(schedule, text="Enable automatic backups", variable=self.schedule_enabled_var).grid(row=1, column=0, columnspan=2, sticky="w", pady=(10, 0))
            ttk.Label(schedule, text="Preset").grid(row=2, column=0, sticky="w", pady=(10, 0))
            ttk.Combobox(schedule, textvariable=self.schedule_preset_var, values=["manual", "hourly", "daily", "weekly", "custom"], width=18, state="readonly").grid(row=2, column=1, sticky="w", pady=(10, 0))
            ttk.Label(schedule, text="Custom minutes").grid(row=3, column=0, sticky="w", pady=(10, 0))
            ttk.Entry(schedule, textvariable=self.schedule_custom_var, width=12).grid(row=3, column=1, sticky="w", pady=(10, 0))
            ttk.Label(schedule, text="I/O yield milliseconds per chunk").grid(row=4, column=0, sticky="w", pady=(10, 0))
            ttk.Entry(schedule, textvariable=self.io_yield_var, width=12).grid(row=4, column=1, sticky="w", pady=(10, 0))

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
            value = filedialog.askdirectory()
            if value:
                variable.set(value)

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
                if not self.recovery_usb_device_var.get() and usb_choices:
                    self.recovery_usb_device_var.set(usb_choices[0]["display"])
                if not self.guided_target_disk_var.get() and guided_choices:
                    self.guided_target_disk_var.set(guided_choices[0]["display"])
            except Exception as exc:
                self.message_var.set(str(exc))

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
                self.message_var.set(response.get("message", "Repository path updated."))
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
                    "recovery_key": self.repo_recovery_key_var.get().strip(),
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

            self.status_var.set(
                f"{'Busy: ' + current_job['name'] + ' — ' + current_job['stage'] if current_job else 'Idle'}"
            )

            self.summary_labels["machine"].configure(text=f"{settings.get('machine_label')} ({settings.get('machine_id')})")
            self.summary_labels["repo"].configure(text=settings.get("repo_path", ""))
            self.summary_labels["last_good"].configure(text=state.get("last_success_at") or "—")
            self.summary_labels["last_run"].configure(text=state.get("last_run_at") or "—")
            self.summary_labels["last_sync"].configure(text=state.get("last_sync_at") or "—")
            self.summary_labels["recovery_key"].configure(text=state.get("recovery_key_path") or "—")

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
                    str(snap.get("archive_bytes", 0)),
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
                    "recovery_key": self.export_recovery_key_var.get().strip(),
                })
                if not response.get("ok"):
                    raise AegisError(response.get("error", "Unknown daemon error"))
                self.message_var.set(response.get("message", "Bundle export started."))
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
                    "recovery_key": self.repo_recovery_key_var.get().strip(),
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

        def save_settings(self) -> None:
            try:
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
                payload = {
                    "version": 1,
                    "machine_id": self.dashboard_payload.get("settings", {}).get("machine_id", machine_id()),
                    "machine_label": self.machine_label_var.get().strip() or hostname(),
                    "repo_path": self.repo_path_var.get().strip() or DEFAULT_REPO,
                    "encryption_enabled": bool(self.encryption_var.get()),
                    "schedule": {
                        "enabled": bool(self.schedule_enabled_var.get()),
                        "preset": self.schedule_preset_var.get().strip() or "manual",
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
                response = send_daemon_request({"action": "save_settings", "settings": payload})
                if not response.get("ok"):
                    raise AegisError(response.get("error", "Unknown daemon error"))
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
    export.add_argument("--recovery-key")
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
    restore.add_argument("--recovery-key")
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
            return init_command(args.repo, args.label, args.encryption == "on")
        if cmd in ("status", "dashboard"):
            return print_status_json()
        if cmd == "list-snapshots":
            return list_snapshots_command()
        if cmd == "list-disks":
            return list_disks_command()
        if cmd == "backup-now":
            return backup_now_command(args.profile, args.direct)
        if cmd == "export-bundle":
            return export_bundle_command(args.snapshot, args.output, args.password, args.recovery_key, args.direct)
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

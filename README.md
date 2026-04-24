# Aegis

This software is currently in Alpha. The core backup, restore, and recovery USB features are foundationally complete and tested on Debian based systems (Ubuntu, Mint, Pop!_OS). Constellation Mode remains in active development and is not ready yet.

I built Aegis to protect my own Linux workstation, and I use it daily. However, because system configurations vary wildly, this software is provided "as is" without absolute guarantees. Please be smart with your critical data and always maintain multiple backups across multiple physical devices. We are not liable for any data loss.


## What This Software Is

Aegis is a compact, highly autonomous, and comprehensive disaster recovery and backup suite engineered specifically for Debian based Linux systems (such as Ubuntu, Linux Mint, and Pop!_OS). 

Designed with an extreme focus on portability and self sufficiency, the entire application is contained within a single Python file. Despite its standalone nature, it features a graphical user interface, a command line interface, a background scheduling daemon, a deduplicating cryptographic backup engine, a peer to peer synchronization protocol, and a custom recovery operating system builder. 

## What It Can Do

Aegis is built to handle everything from daily file protection to complete hardware migrations and bare metal disaster recovery. Its primary capabilities include:

* **Dual Profile Snapshots:**
    * **Full Recovery:** Captures an exact 1:1 state of the machine for restoring to identical hardware or recovering from catastrophic drive failure.
    * **Portable Migration:** Captures user data, configurations, and installed applications, while intentionally omitting hardware specific drivers and static networking configurations to allow seamless migration to completely different hardware.
* **Automated Bare Metal Restores:** Orchestrates the entire disk restore process, including wiping targets, generating GPT partition layouts, formatting file systems, and configuring bootloaders (GRUB or systemd-boot).
* **Recovery Media Bootstrapping:** Builds a bootable Debian Live environment directly to a target USB drive using `debootstrap`, injecting the Aegis GUI directly into the live session for immediate disaster recovery.
* **Constellation Mode:** Securely mirrors encrypted backup repositories across a network of configured peers using SSH and `rsync`.
* **Standalone Bundle Export:** Compiles a specific point in time backup into a single, password protected `.avb` (Aegis Vault Bundle) archive file for easy off site storage.
* **Automated Background Daemon:** Runs silently as a systemd service, executing scheduled backups, enforcing repository size limits, and triggering native desktop notifications for job statuses.

## How It Works

Aegis abstracts complex Linux system administration tasks into an automated pipeline:

* **Architecture:** The software operates in a client server model over a local UNIX socket (`/run/aegisvault/daemon.sock`). The root privileged background daemon handles all heavy lifting, while the CLI and GUI act as unprivileged clients that issue JSON-RPC commands to the daemon.
* **Chunking & Deduplication Engine:** During a backup, Aegis pipes the filesystem into a `tar` stream. To maximize deduplication and prevent "tar shift" (where a single changed byte alters the entire subsequent stream), Aegis actively scans the byte stream for 512 byte `ustar` tar header boundaries, cutting chunks cleanly at natural file limits.
* **Encryption Security:** All data chunks are individually encrypted using AES-GCM. The machine specific encryption keys are wrapped using Scrypt derived user passwords and stored natively within the host's encrypted `systemd-creds` store, ensuring plaintext keys are never exposed on the disk.
* **System Metadata Capture:** Alongside file data, Aegis generates comprehensive metadata manifests. It records package states (APT, Flatpak, Snap), kernel versions, partition tables, `fstab` layouts, and hardware configurations to intelligently reconstruct the environment later.

## How It Is Unique

Aegis diverges significantly from traditional Linux backup tools (like Timeshift, Deja Dup, Borg, or Clonezilla) by bridging the gap between file level versioning and block-level cloning.

* **Hardware Agnostic Migration:** This is Aegis's standout feature. Unlike Clonezilla (which clones block by block) or Timeshift (which blindly restores root file systems), Aegis's "Portable Migration" actively scrubs incompatible hardware states during a restore. It automatically removes proprietary kernel modules (Nvidia, System76, Broadcom), scrubs `initramfs` hooks, clears static network rules, and regenerates `fstab`. This allows you to back up an Intel/Nvidia desktop and restore it directly onto an AMD laptop without encountering kernel panics or boot loops.
* **Intelligent Bootloader Reconstruction:** File level deduplicating backup tools typically leave the user to manually format target drives, `chroot` into the restored environment, and reinstall the bootloader. Aegis's "Guided Restore" automates this. It maps new UUIDs, writes fresh EFI partition tables, and executes complex `chroot` logic to reinstall UEFI/BIOS GRUB or `systemd-boot`/`kernelstub` automatically.
* **Monolith:** Traditional disaster recovery requires a fragmented stack: a frontend GUI, a backend archiver, and a separate bootable ISO flashed via a third party tool. Aegis consolidates the scheduler, the GUI, the chunking backend, and the recovery OS generator into one script.
* **Native Systemd Integration:** Aegis does not rely on plaintext key files or custom cron jobs. It generates its own systemd service units, utilizes systemd credential management for cryptographic keys, and manages background scheduling entirely through modern Linux daemon standards.

## Install

Install with 1 command:

```bash
curl -fsSL https://raw.githubusercontent.com/MagnetosphereLabs/Aegis/main/install.sh | sudo bash -s -- install
```

Update with 1 command:

```bash
curl -fsSL https://raw.githubusercontent.com/MagnetosphereLabs/Aegis/main/install.sh | sudo bash -s -- update
```

Uninstall with 1 command:

```bash
curl -fsSL https://raw.githubusercontent.com/MagnetosphereLabs/Aegis/main/install.sh | sudo bash -s -- uninstall
```


## Commands

Open the GUI:

```bash
aegisvault gui
```

View current state:

```bash
aegisvault status
```

Run a manual backup:

```bash
sudo aegisvault backup-now --profile both --direct
```

List snapshots:

```bash
aegisvault list-snapshots
```

Export a single file bundle:

```bash
sudo aegisvault export-bundle SNAPSHOT_ID /path/to/backup.avb --password "your-bundle-password" --direct
```

Restore from repository:

```bash
sudo aegisvault restore --snapshot SNAPSHOT_ID --target /mnt/target-root --direct
```

Restore from repository with another machines recovery key:

```bash
sudo aegisvault restore --snapshot SNAPSHOT_ID --recovery-key "YOUR-RECOVERY-KEY" --target /mnt/target-root --direct
```

Restore from a local bundle file:

```bash
sudo aegisvault restore --bundle /path/to/backup.avb --bundle-password "your-bundle-password" --target /mnt/target-root --direct
```

Restore from a hosted bundle URL:

```bash
sudo aegisvault restore --url "https://example.com/backup.avb" --bundle-password "your-bundle-password" --target /mnt/target-root --direct
```

Create recovery USB:

```bash
sudo aegisvault create-recovery-usb --device /dev/sdX --direct
```

Guided full restore from a Full Recovery snapshot:

```bash
sudo aegisvault restore --snapshot SNAPSHOT_ID --guided --target-disk /dev/sdX --direct
```

Guided full restore from an encrypted bundle:

```bash
sudo aegisvault restore --bundle /path/to/backup.avb --bundle-password "your-bundle-password" --guided --target-disk /dev/sdX --direct
```

Sync configured peers now:

```bash
sudo aegisvault sync-peers --direct
```

The daemon runs as root. Desktop users talk to it through a Unix socket. The installer adds your user to the `aegisvault` group so the UI can control the daemon without running the whole GUI as root.

## Recovery key

During initialization AegisVault writes a file like:

```text
/var/lib/aegisvault/RECOVERY-KEY-xxxxxxxx.txt
```

Copy that file somewhere safe. That key is how you can decrypt the repository key for that machine on a different system.

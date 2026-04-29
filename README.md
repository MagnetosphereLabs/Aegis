# Aegis

This software is currently in Alpha. The core backup, restore, and recovery USB features are foundationally complete and tested on Debian based systems (Ubuntu, Mint, Pop!_OS). Constellation Mode remains in active development and is not ready yet.

I built Aegis to protect my own Linux workstation, and I use it daily. However, because system configurations vary wildly, this software is provided "as is" without absolute guarantees. Please be smart with your critical data and always maintain multiple backups across multiple physical devices. We are not liable for any data loss.


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

# Aegis: Architecture and Capabilities

Aegis is a compact, robust Linux backup and bare metal recovery application designed primarily for Debian based systems. It differs from traditional Linux backup tools by packing an entire suite of interfaces and engines into a standalone script, focusing heavily on deduplication, system portability, and hardware agnostic restores.

Below is the technical documentation explaining how Aegis operates under the hood, structured for both casual users and power users.

## The Single File Architecture

Aegis is written entirely in **Python 3**. It acts as a high level orchestrator for standard Linux shell languages and utilities (Bash, tar, udevadm, parted, apt, etc.). 

By keeping everything in one file, Aegis eliminates complex dependency trees. Inside this single file resides:
* **A graphical user interface (GUI)** built with Tkinter.
* **A command line interface (CLI)** for scripting.
* **A background daemon** that communicates via local Unix sockets (`/run/aegisvault/daemon.sock`) to run scheduled tasks seamlessly.
* **The core backup and bare-metal restore engines.**

## Linux and Debian Integration

Aegis bypasses high level abstractions and talks directly to the Linux kernel and package managers.
* **Hardware parsing:** It reads directly from `sysfs` and interacts with `udev` and `blockdev` to safely lock, flush, partition, and format drives without relying on heavy external disk managers.
* **Debian/Ubuntu/Pop!_OS optimization:** It leverages `dpkg` and `apt`. During a backup, it catalogs your exact OS release, kernel versions, manual apt packages, Flatpaks, and Snaps. During a restore, it uses `chroot` environments to actively interact with the `apt` cache, dynamically reinstalling the correct packages for the target environment.

## Backup Engine and Deduplication

Aegis creates point in time snapshots using a highly efficient deduplication engine.

1.  **Archiving:** It reads your system using `tar` to preserve precise Linux file permissions, ACLs, and extended attributes.
2.  **Chunking:** As the stream is read, Aegis cuts the data into standardized chunks (defaulting to 16 MiB). 
3.  **Deduplication:** Aegis calculates a SHA-256 hash for every chunk. It checks the backup repository (`/var/backups/aegisvault/objects/`); if that hash already exists, Aegis simply references it and moves on. This means unchanged files, or even identical parts of changed files, are never stored twice.
4.  **Encryption:** If the chunk is new, Aegis encrypts it using AES-GCM cryptography before writing it to the disk.

## Exporting and Portable Restores

Aegis is built around the reality that hardware can fail and users upgrade their computers. 

* **Encrypted Exports:** You can export any backup snapshot as a single, standalone encrypted bundle file (`.avb`). You can save this file to an external USB drive, plug it into a completely different computer, and use Aegis to restore the system directly from that bundle.
* **Portable Migrations:** When moving from one machine to another (e.g., an old desktop to a new one), Aegis performs a "Portable State" restore. It intelligently strips out old hardware identities. It drops your old `/etc/fstab`, removes proprietary drivers (like old NVIDIA or System76 modules), and cleans up `dracut` and `initramfs` configurations. This guarantees your Linux installation will boot cleanly on the new hardware without kernel panics caused by missing legacy drivers.

## Apple T2 Hardware Support

Restoring Linux onto an Intel Mac with an Apple T2 security chip (2018–2020) requires highly specific drivers. Aegis handles this gracefully.

* **The Philosophy:** Aegis does not try to configure every piece of hardware perfectly. Its job is to get the fundamentals working so you can boot up, log in, and access your data.
* **How it works:** If you generate a T2 enabled Aegis Recovery USB, it automatically injects custom `apt` repositories to fetch specialized T2 kernels.
* **Automated Injection:** It modifies the `initramfs` to include the `apple-bce` module, maps the Touch Bar using `tiny-dfr`, applies DRM modesetting for Xorg graphics, and forces required kernel boot parameters (like `intel_iommu=on`). This ensures the keyboard, NVMe storage, and display work immediately upon your first boot.


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

# Aegis

This software is in alpha, and has been tested on Debian based systems like Ubuntu, Linux Mint, and Pop!_OS. The backup and restore features, including the recovery USB, are foundationally complete, getting mostly UI updates and QOL improvments. Constellation Mode is still being developed. I "put my money where my mouth is" because I use this software myself to backup my own Linux PC. But even though I use this myself, I cannot 100% guarantee that this will work on your system. If you have very important things to backup, I strongly recommend that you keep multiple copies of it on multiple devices.


## What is it?
Aegis is a compact, monolithic Linux backup application designed specifically for Debian based systems (like Linux Mint, Ubuntu, and Pop!_OS). It handles secure system snapshots, bare metal recovery, and hardware agnostic OS migrations.

## What It Can Do

* **Two-Tiered Backup Profiles:**
    * **Full Recovery:** Captures the entire filesystem for a 1:1 bare-metal restore onto the same hardware or a replacement drive.
    * **Portable Migration:** Captures your OS, user data, and package lists, but explicitly excludes hardware-specific driver state (like DKMS, proprietary Nvidia/System76 drivers, and persistent network rules). This allows you to restore your OS onto a completely different computer and have it boot cleanly with your apps and data.
* **Encrypted, Deduplicated Storage:** Backups are chunked, hashed (SHA256) to prevent duplicate data storage, and encrypted at rest using AES-GCM with Scrypt key derivation.
* **Integrated Bare Metal Recovery:** Aegis can dynamically build a custom, bootable Debian recovery environment onto a USB drive using `debootstrap`. Booting from this USB opens the Aegis GUI directly for system restoration.
* **Guided Full Restore:** Aegis handles the entire drive recovery process automatically. It partitions the target disk (GPT, EFI, Root), formats the filesystems, extracts the data, generates a new `fstab`, and seamlessly installs/repairs the bootloader (supporting both GRUB and `systemd-boot`).
* **Constellation Mode (Peer Sync):** Securely mirrors your backups to remote machines or servers using `rsync` over SSH.
* **Portable Bundles (`.avb`):** Exports specific snapshots into standalone, encrypted archive bundles. These can be loaded via URL or local file and restored on foreign machines.
* **Background Daemon & Scheduling:** Runs automatically in the background via a systemd service, honoring custom schedules, storage size limits, and I/O yield constraints to prevent system slowdowns.

## How It Works

Aegis operates via a unified architecture where the GUI, CLI, daemon, and extraction engines all live inside a single Python script. 

1.  **Capture Engine:** When a backup starts, Aegis uses `tar` to accurately capture the filesystem, preserving permissions, ACLs, and extended attributes.
2.  **Data Pipeline:** The raw `tar` stream is ingested by Aegis's internal chunking engine. The data is sliced into chunks, hashed, encrypted, and written to the backup destination as raw objects.
3.  **Metadata Manifests:** Alongside the raw data, Aegis saves a rich JSON manifest. This file records the exact state of the machine at the time of backup, including installed `apt` packages, Flatpaks, Snaps, kernel versions, partition layouts, and OS release data.
4.  **Secure Local Unlocking:** To facilitate unattended, encrypted backups, Aegis integrates directly with `systemd-creds`. It securely encrypts and stores the machine's local unlock key via the systemd credential store, avoiding plaintext passwords sitting in config files.
5.  **IPC / Privilege Separation:** The user-facing Tkinter GUI communicates with the root-level background daemon via a local UNIX socket (`/run/aegisvault/daemon.sock`). When a user interacts with the GUI, Aegis securely escalates privileges using `pkexec` to authorize socket access.
6.  **Active Restoration:** During a restore (especially a Portable Migration), Aegis doesn't just copy files. It actively `chroot`s into the restored target to scrub hardware-specific configs (like dracut configs and module load lists), reinstalls necessary packages, and generates a fresh initramfs tailored to the new hardware.

## How Aegis is Different

Typical Linux backup tools are generally categorized as either file level archivers or snapshot managers. Aegis blurs these lines and introduces several unique paradigms:

* **The "Portable Migration" Concept:** Standard backup tools fail catastrophically if you restore a backup containing Nvidia drivers and custom X11 configs onto a laptop with Intel graphics. Aegis solves this by actively sanitizing the restored OS. It strips out proprietary drivers, DKMS modules, and hardcoded machine IDs, making your Linux install completely hardware-agnostic during a move.
* **Single File Monolith:** Aegis does not rely on a fragmented stack of frontends, backends, and wrapper scripts. The daemon, the graphical interface, the command-line tool, and the recovery OS bootstrapper are all packaged into one single `aegisvault.py` file.
* **It Builds Its Own Recovery Media:** Instead of requiring you to download a live ISO and figure out how to install your backup software onto it, Aegis builds its own live environment. Give it a USB stick, and it bootstraps a minimal Debian OS with Aegis pre-configured to launch on boot.
* **Smart Bootloader Healing:** Restoring a Linux system usually requires manual `chroot` gymnastics to fix GRUB or `systemd-boot` so the BIOS can actually find the OS. Aegis completely automates this. It maps the new UUIDs, writes the EFI variables, configures the bootloader, and generates the initramfs silently in the background.

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

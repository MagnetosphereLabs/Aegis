This software is in pre-alpha v1 and is not ready to install on your device. Coming soon ™️

# Aegis

Aegis is a compact backup product for Debian-based Linux systems such as Pop!_OS, Ubuntu, Linux Mint, and Debian.

## What it does

Aegis gives you:

- **two snapshot kinds from one workflow**
  - **Full Recovery** for same-machine disaster recovery
  - **Portable System State** for moving your setup to different hardware
- **encrypted backups**
- **restore from a local backup or restore from a hosted encrypted file via a URL**
- **guided full restore that wipes a selected target disk and makes it bootable again**
- **bootable recovery USB creation from inside the app**
- **manual or automatic backups**
- **optional Constellation peer mirroring over SSH and rsync**
- **native desktop GUI on Linux via Tkinter**
- **CLI and daemon in the same app**
- **slight per-chunk I/O yielding** to smooth heavy bursts

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

## How it works

### Repository backups

Aegis stores snapshots in an encrypted, chunked repository:

- manifests live under `machines/<machine-id>/snapshots`
- encrypted chunk objects live under `objects/<machine-id>/<prefix>`
- each machine gets a local repository key for unattended scheduled backups
- that repository key is also wrapped with a human recovery key so another system can restore it later

### Full Recovery

It backs up the system from `/` while excluding unsafe runtime paths such as:

- `/dev`
- `/proc`
- `/sys`
- `/run`
- `/tmp`
- `/var/tmp`
- removable-media mount roots
- the active repository path itself

Restore this in one of two ways:

- **guided full restore** from AegisVault Recovery USB, which wipes a chosen target disk, recreates a bootable layout, restores the snapshot, rewrites `fstab`, and reinstalls the bootloader
- **advanced manual restore** to an offline-mounted target root if you prefer to manage mounts yourself


### Portable System State

This is the "carry my setup to new hardware" profile.

By default it includes:

- `/home`
- `/etc`
- `/opt`
- `/usr/local`
- `/var/lib/flatpak`
- `/var/lib/snapd`
- `/var/snap`

It excludes hardware-bound items by default, including:

- host identity files
- hardware-tied kernel module trees
- DKMS build state
- caches

### Single-file bundles

Any snapshot can be exported as one encrypted `.avb` file.

That bundle can be:

- copied to any disk
- uploaded to remote storage
- restored later from a local path
- restored later from an HTTPS URL

### Constellation mode

Constellation is the optional pro grade mirror mode.

You install the same software on other machines, configure SSH peers, and AegisVault mirrors encrypted repository namespaces across them with rsync.

That means a fleet of home machines or VPS nodes can hold each other's encrypted backup data.

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

## GUI

The GUI gives you five tabs:

- **Overview**
- **Back Up**
- **Restore**
- **Constellation**
- **Settings**

The daemon runs as root. Desktop users talk to it through a Unix socket. The installer adds your user to the `aegisvault` group so the UI can control the daemon without running the whole GUI as root.

## Recovery key

During initialization AegisVault writes a file like:

```text
/var/lib/aegisvault/RECOVERY-KEY-xxxxxxxx.txt
```

Copy that file somewhere safe. That key is how you can decrypt the repository key for that machine on a different system.

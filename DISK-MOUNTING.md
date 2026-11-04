# APFS Disk Mounting and VFS Operations Guide

Read-write mounts can be requested for testing, but APFS mutation support is
experimental and has not been validated on all APFS volumes. Test only with
disposable volumes and keep backups.
Encrypted required metadata is unsupported.

---

## Standard Mount Commands

### 1. Direct Mount via `mount` (VFS Frontend)
To mount an APFS partition or device:

```bash
mount -t apfs -o rw /dev/sd0e /mnt
```

* `-t apfs`: Specifies the APFS filesystem driver.
* `-o rw`: Requests a read-write mount for testing.
* `/dev/sd0e`: The target block device partition containing the APFS container.
* `/mnt`: The target mount point directory.

---

### 2. Direct Invocation via `mount_apfs`
You can also invoke the filesystem-specific mount helper directly:

```bash
mount_apfs -o rw /dev/sd0e /mnt
```

---

### 3. Mounting from a Disk Image via Virtual Node Disk (`vnd`)
When working with raw APFS disk images (e.g., container images or virtual disks), configure a `vnd` device before mounting:

```bash
# Associate the image file with a virtual block device
vnconfig vnd0 /path/to/apfs_container.img

# Mount the virtual device read-write for testing
mount -t apfs -o rw /dev/vnd0a /mnt
```

When finished, unmount and detach the device cleanly:
```bash
umount /mnt
vnconfig -u vnd0
```

---

## Useful Performance & Safety Mount Options

To optimize I/O throughput, minimize write amplification on flash/SSD storage, and protect system security:

```bash
mount -t apfs -o rw,noatime,nodev,nosuid /dev/sd0e /mnt
```

* `noatime`: Disables access time updates on read operations.
* `nodev`: Prevents interpretation of character or block special devices for enhanced security.
* `nosuid`: Disables set-user-identifier and set-group-identifier execution bits.

---

## Unmounting

```bash
# Cleanly unmount the filesystem
umount /mnt
```

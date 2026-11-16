#!/bin/sh
set -eu

if [ $# -lt 1 ]; then
    echo "Usage: $0 user@remote_host [remote_port]"
    exit 1
fi

REMOTE_HOST="$1"
PORT="${2:-22}"

DESTDIR="/Users/granowski/netbbuild1/destdir.evbarm"
KERNEL="/Users/granowski/netbbuild1/sys/arch/evbarm/compile/GENERIC64/netbsd"

echo "Verifying local binaries before transfer..."
for f in "$KERNEL" "$DESTDIR/sbin/mount_apfs" "$DESTDIR/sbin/newfs_apfs"; do
    if [ ! -f "$f" ]; then
        echo "Error: Required artifact not found: $f" >&2
        exit 1
    fi
done

echo "Connecting via SFTP to ${REMOTE_HOST}:${PORT}..."
sftp -P "$PORT" -b - "$REMOTE_HOST" <<EOF
# Upload kernel to /netbsd.new for safe swap
put "$KERNEL" /netbsd.new
chmod 755 /netbsd.new

# Upload APFS utilities
put "$DESTDIR/sbin/mount_apfs" /sbin/mount_apfs
chmod 755 /sbin/mount_apfs

put "$DESTDIR/sbin/newfs_apfs" /sbin/newfs_apfs
chmod 755 /sbin/newfs_apfs

put "$DESTDIR/sbin/mkfs.apfs" /sbin/mkfs.apfs
chmod 755 /sbin/mkfs.apfs

# Upload kernel module if present
-mkdir -p /stand/evbarm/11.99.11/modules/apfs
-put "$DESTDIR/stand/evbarm/11.99.11/modules/apfs/apfs.kmod" /stand/evbarm/11.99.11/modules/apfs/apfs.kmod

# Upload RUMP test libraries and binaries
-put "$DESTDIR/usr/lib/librumpfs_apfs."* /usr/lib/
-mkdir -p /usr/tests/fs/apfs
-put "$DESTDIR/usr/tests/fs/apfs/"* /usr/tests/fs/apfs/

quit
EOF

echo "Upload completed successfully."
echo "Remote activation instructions:"
echo "  1. SSH into the remote machine."
echo "  2. Backup old kernel:  mv /netbsd /netbsd.old"
echo "  3. Activate new kernel: mv /netbsd.new /netbsd"
echo "  4. Reboot:             reboot"

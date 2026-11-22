# Current APFS feature coverage

This is an inventory of code paths in `sys/fs/apfs`, not a compatibility
claim or a statement that every path has passed kernel-level testing. "Present"
means there is an implementation in the current source; edge cases, crash
recovery, and interoperability with all APFS variants still need validation.

## Mounting and metadata

| Area | Current code |
|---|---|
| Container and volume discovery | Reads the container superblock, selects a valid checkpoint, locates a volume superblock through the object map, and validates the root filesystem tree. |
| Checksums and integrity | Validates APFS Fletcher checksums for ordinary metadata. Sealed-volume metadata supports SHA-256, SHA-512/256, SHA-384, and SHA-512 root-hash verification. |
| Block sizes | Accepts container block sizes from 4 KiB through 64 KiB, provided the size is a multiple of the device sector size. |
| Object maps and B-trees | Includes object-map lookup, B-tree search and iteration, and copy-on-write B-tree record insert/remove paths. |
| Space accounting | Parses and validates Space Manager structures and has block reservation/allocation and copy-on-write Space Manager update paths. Read-write mounting is refused when the Space Manager cannot be validated safely. |
| Vnodes | Loads inode records into vnodes and exposes the volume root, basic attributes, and `statvfs` information. |
| Mount lifecycle | Implements mount, root lookup, sync, and unmount. Mount updates, snapshots, file-handle conversion, and mount-as-root are not implemented. |
| Formatting | `newfs_apfs` creates a single unencrypted, unsealed volume in a 4 KiB-block container. Other block sizes, multi-volume containers, encryption, and sealing are unsupported. |

Encrypted volumes are not supported. Sealed volumes have integrity metadata
verification code but are only accepted read-only; a read-write mount is
rejected.

## Namespace and file operations

| Operation | Current code |
|---|---|
| Lookup | Handles `.`, `..`, directory-record lookup, and the missing final component for create. |
| Regular-file creation | Creates an inode and directory record in a transaction. Empty-file creation does not allocate a data extent. |
| Directory creation/removal | Has create and remove paths; directory removal checks for directory records before removing the directory. |
| Regular-file removal | Removes a directory record and updates the inode/link count; on the last link it removes the inode and queues extents for freeing. |
| Rename | Has a rename path with type checks and optional destination removal. Cross-volume rename is rejected. |
| Symbolic links | Has create and readlink paths backed by file extents. |
| Directory iteration | Emits `.` and `..`, then iterates directory records and reports EOF after a complete tree scan. Returned entries currently use `DT_UNKNOWN`. |
| Access and attributes | Uses genfs access checks and reports inode mode, ownership, size, link count, and timestamps. Attribute updates include size (truncate), mode, uid/gid, atime, and mtime. |
| Open/close | The APFS regular vnode open and close handlers currently return success without additional work. |

The vnode operation table uses NetBSD genfs helpers for several generic
operations, including locking, accessx, mmap, seek, pathconf, and paging.
Their presence in the table does not imply APFS-specific support for every
related filesystem feature.

## File data

- Reads search the extent tree, read physical blocks, and return zeroes for
  holes.
- Writes use block-sized physical allocations, preserve existing data for
  partial-block writes when an old extent is found, write new data blocks,
  update extent records and inode size/timestamps, and commit metadata.
- Truncation has a metadata path that removes extents beyond the new size.
- `bmap` resolves logical file blocks to device blocks and marks holes; the
  strategy handler forwards I/O to the underlying device vnode.
- `fsync` and filesystem sync forward synchronization to the device.

These are implemented paths, not a guarantee of full POSIX semantics or
validated behavior for every failure case. In particular, ordinary image
tests do not exercise NetBSD's kernel buffer cache, vnode locking, or VOP
dispatch. See [Create and write paths](write-path.md) and
[Locking and stall diagnosis](locking-and-stalls.md).

## Current gaps and visible limits

- Hard links, `mknod`, `fallocate`, and `fdiscard` are unsupported.
- Mount updates, snapshots, file handles, and mounting as the root filesystem
  are unsupported.
- The directory-record name hash in `apfs_vnops.c` validates UTF-8 and folds
  ASCII uppercase for case-insensitive volumes. It returns `EOPNOTSUPP` for
  non-ASCII names when case-insensitive or normalization-insensitive behavior
  is required. Although Unicode transform tables and a transform helper are
  present in the source, this lookup/hash path does not currently use them.
- Some name operations impose shorter implementation limits than the
  filesystem's advertised `f_namemax`: symlink and rename names are limited to
  `APFS_MODIFIED_NAMELEN` (32 bytes). This is narrower than lookup and regular
  file/directory creation.
- Directory entries do not yet report their actual vnode type (`d_type` is
  `DT_UNKNOWN`).
- Code-level coverage does not establish safety for arbitrary APFS feature
  combinations, concurrent workloads, power loss, or recovery after an
  interrupted write.

`APFS_DEBUG` is enabled by default during active development. Kernel traces
are useful for diagnosing path boundaries but are not a substitute for
runtime testing and lock/stack diagnostics.

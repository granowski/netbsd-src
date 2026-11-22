# Space Manager, bitmaps, and filesystem operations

This guide explains how the current NetBSD APFS implementation connects
filesystem requests to physical block allocation. It describes the code in
`sys/fs/apfs`, not every APFS format feature or a claim of full compatibility.
The implementation is under active development; use a copy of an image for
experiments and do not treat these notes as recovery instructions.

## The pieces and their relationship

The Space Manager (Spaceman) is the container-level authority for physical
block availability. In the supported layout, its data describes one device
and organizes that device into chunks:

1. The **Space Manager object** supplies geometry: block size and count,
   blocks per chunk, chunks per CIB, the CIB addresses, device free count,
   reserve information, and free-queue fields.
2. A **Chunk Information Block (CIB)** describes a group of chunks. For each
   chunk it records the starting address, block count, free-block count, XID,
   and allocation-bitmap address.
3. A **bitmap** has one bit per physical block in its chunk. In the layout
   currently validated and allocated by this implementation, a clear bit is
   free and a set bit is allocated. Bits are numbered least-significant-bit
   first within each byte.

```text
filesystem request
       |
       v
VOP operation -> APFS transaction -> reserve physical blocks
                                      |
                       Space Manager -> CIB -> chunk bitmap
                                      |
       copy-on-write data / B-trees / allocator metadata
                                      |
                         checkpoint map + container superblock
```

The Space Manager does not say which file owns an allocated block. File
ownership is represented separately by filesystem metadata: inode records,
extent records, directory records, object-map entries, and B-tree nodes. An
extent maps a file's logical range to a physical block range; the Space
Manager bitmap tracks whether that physical block is available for reuse.

## Reading the allocator hierarchy

Let `B` be the container block size, `N` the number of blocks, and `C` the
number of blocks per chunk. The expected number of chunks is
`ceil(N / C)`. The last chunk may contain fewer than `C` valid blocks.
Chunks are grouped into CIBs according to the Space Manager's
`chunks_per_cib` value. The current validator checks that these values agree
with the declared device geometry and that each CIB and bitmap address is
inside the container.

The validator reads each CIB and its referenced bitmap. It checks the object
checksums and types, CIB index and chunk count, chunk start/count, bitmap
polarity, the per-chunk free count, and the aggregate device free count. It
also rejects unsupported secondary-device/CAB layouts and excludes known
reserved or unsafe ranges from allocation candidates. A volume is not
considered safe for read-write use if the Space Manager cannot be validated.

A chunk may have no bitmap address when it is entirely free; the validator
accepts that only when its CIB reports every valid block in the chunk free.
The allocator itself searches bitmap-backed chunks. A candidate also has to
be within the device, pass container exclusion checks, and not overlap an
in-memory reservation already made by another operation.

## Allocation is reservation followed by publication

Block allocation has two distinct moments:

### 1. Find and reserve

`apfs_tx_begin()` serializes mutations with `am_lock` and assigns the
transaction's next XID. `apfs_tx_alloc_block()` calls `apfs_resv_alloc()`.
That routine reads the Space Manager geometry, walks chunks from the in-memory
allocation cursor, consults the CIB free count, then reads the bitmap and
searches for a run of clear bits. It skips excluded and already-reserved
blocks.

When it finds a range, it records it in the reservation pool and in the
transaction context. This prevents a second allocator request from selecting
the same block before the transaction commits. Reservation alone does **not**
persistently change the bitmap or the CIB count.

`rp_lock` protects the in-memory reservation list and cursor. The current
allocator holds this lock while reading CIB and bitmap buffers; those reads
can block. See [Locking and stall diagnosis](locking-and-stalls.md) for the
wait boundaries and lock-order caveat.

### 2. Write copy-on-write metadata and publish

On commit, `apfs_spaceman_tx_update()` incorporates transaction reservations
and queued frees. It copies bitmap contents in memory, sets bits for allocated
blocks, clears bits for freed blocks, and adjusts per-chunk free counts. It
allocates new bitmap and CIB blocks rather than overwriting the old versions.
Because those replacement metadata blocks also need allocation, the update
iterates to include the new reservations. It then writes the changed bitmap
blocks, CIBs, and a new Space Manager object, and adds the new Spaceman
mapping to the transaction's checkpoint mappings.

Filesystem B-tree and object-map updates are also copy-on-write: their new
physical blocks and mappings join the same transaction. The commit writes the
checkpoint-map blocks and then a new container superblock in the descriptor
ring. That superblock publishes the new XID and descriptor-ring position.
Only after this publication does the in-memory mount state advance and the
transaction release its reservations and `am_lock`.

If work fails before publication, transaction abort releases reservations and
restores the saved in-memory volume superblock. The exact on-disk crash
behavior depends on which writes completed; checkpoint selection and
validation determine which consistent version a later mount can use. See
[Create and write paths](write-path.md) for the create/write call sequence.

## How filesystem operations use blocks

### Creating an empty file

Creating a regular file inserts an inode record and a directory record into
the filesystem B-tree, then updates volume metadata and commits. An empty file
has no file-data extent, so `touch newfile` does not need to allocate a data
block. It can still allocate blocks for copy-on-write B-tree nodes, object-map
metadata, the volume superblock, and the Space Manager structures needed to
record those allocations.

### Writing file data

`apfs_vop_write()` allocates a data block for each block-sized portion of the
write, writes the data, inserts or replaces the file's extent record, updates
the inode size and timestamps, and commits the metadata transaction. A
partial-block write initializes the new block from the old extent where
available, or with zeroes for a hole. Replaced physical blocks are queued for
freeing in the transaction rather than reused during the same reservation
search.

### Removing or replacing data

Removing the last link to a file can remove its inode and extent records and
queue the old physical extents for freeing. Truncation and overwrites can
also queue replaced extents. At commit, the Space Manager update applies
those frees to bitmap/CIB accounting and updates its free-queue fields. The
free-queue and crash-recovery behavior is still implementation work and must
not be assumed equivalent to mature APFS behavior in all workloads.

## Practical trace interpretation

- `tx_begin ... acquired am_lock` means the operation entered the serialized
  metadata transaction.
- `tx_alloc ... begin` followed by `resv_alloc read CIB` or `read bitmap`
  identifies allocation metadata being scanned.
- `resv_alloc success` means a physical range was reserved in memory; it does
  not by itself mean the block allocation was committed on disk.
- `spaceman_update ... complete` means allocator metadata staging finished,
  not that the checkpoint was necessarily published.
- `checkpoint map write` and `container superblock write` trace commit
  publication. A mount may reject a newer checkpoint and choose an older one
  if validation fails.

The source trace points are useful for locating a wait, but a trace alone
cannot establish a lock cycle or prove that a machine-wide hang is caused by
APFS. Capture kernel stacks and lock-owner diagnostics when possible.

## Scope and caveats

The implementation has a deliberately restricted Space Manager validator
and writer. In particular, its current validation rejects layouts involving
unsupported CAB or secondary-device metadata, and its per-transaction
Space Manager update has fixed limits for the number of changed chunks and
CIBs. Bitmap allocation, delayed frees, concurrent workloads, power-loss
recovery, and interoperability across APFS variants still need broader
testing. A direct image test can validate on-disk structures but does not
exercise NetBSD buffer-cache waits, vnode locks, or VOP dispatch.

The `newfs_apfs` utility creates a minimal, single-volume container with a
4 KiB block size, an unencrypted and unsealed volume, initial Space Manager
metadata, OMaps, and a root filesystem tree. It does not support multiple
volumes, encryption, sealing, or other block sizes. The formatter invalidates
the old container superblock before writing metadata and activates the new
checkpoint only after the metadata is written.

Relevant implementation areas:

- `apfs_validate_spaceman()` validates geometry, CIBs, bitmaps, and free
  counts.
- `apfs_resv_alloc()` searches bitmaps and records in-memory reservations.
- `apfs_spaceman_tx_update()` stages copy-on-write bitmap, CIB, and Space
  Manager updates.
- `apfs_tx_commit()` publishes checkpoint maps and the container superblock.
- `apfs_vop_create()` / `apfs_create_file()` create inode and directory
  records; `apfs_vop_write()` writes extents.

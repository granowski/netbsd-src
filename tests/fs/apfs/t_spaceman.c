/*	$NetBSD$	*/

/*
 * Standalone test harness for APFS Space Manager validation (Milestone 1).
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>

#ifdef __APPLE__
#include <libkern/OSByteOrder.h>
#define htobe16(x) OSSwapHostToBigInt16(x)
#define htole16(x) OSSwapHostToLittleInt16(x)
#define be16toh(x) OSSwapBigToHostInt16(x)
#define le16toh(x) OSSwapLittleToHostInt16(x)
#define htobe32(x) OSSwapHostToBigInt32(x)
#define htole32(x) OSSwapHostToLittleInt32(x)
#define be32toh(x) OSSwapBigToHostInt32(x)
#define le32toh(x) OSSwapLittleToHostInt32(x)
#define htobe64(x) OSSwapHostToBigInt64(x)
#define htole64(x) OSSwapHostToLittleInt64(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#define le64toh(x) OSSwapLittleToHostInt64(x)
#define DEV_BSIZE 512
#else
#include <sys/endian.h>
#include <sys/param.h>
#endif

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif
#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

/* APFS Data Structures */
typedef int64_t  apfs_paddr_t;
typedef uint64_t oid_t;
typedef uint64_t xid_t;

typedef struct prange {
    apfs_paddr_t pr_start_paddr;
    uint64_t pr_block_count;
} prange_t;

#define MAX_CKSUM_SIZE 8
#define NX_NUM_COUNTERS 32
#define NX_EPH_INFO_COUNT 4
#define APFS_MAX_HIST 8
#define APFS_VOLNAME_LEN 256
#define APFS_MODIFIED_NAMELEN 32
#define BTREE_NODE_HASH_SIZE_MAX 64

typedef struct apfs_uuid_s {
    uint32_t time_low;
    uint16_t time_mid;
    uint16_t time_hi_and_version;
    uint8_t  clock_seq_hi_and_reserved;
    uint8_t  clock_seq_low;
    uint8_t  node[6];
} apfs_uuid_t;

typedef struct obj_phys {
    uint8_t  o_cksum[MAX_CKSUM_SIZE];
    oid_t    o_oid;
    xid_t    o_xid;
    uint32_t o_type;
    uint32_t o_subtype;
} obj_phys_t;

#define OBJECT_TYPE_MASK            0x0000ffff
#define OBJECT_TYPE_FLAGS_MASK      0xffff0000

#define OBJ_CONTAINER_SUPERBLOCK    0x00000001
#define OBJ_BTREE                   0x00000002
#define OBJ_BTREE_NODE              0x00000003
#define OBJ_SPACEMAN                0x00000005
#define OBJ_SPACEMAN_CAB            0x00000006
#define OBJ_SPACEMAN_CIB            0x00000007
#define OBJ_SPACEMAN_BITMAP         0x00000008
#define OBJ_OMAP                    0x0000000b
#define OBJ_CHECKPOINT_MAP          0x0000000c
#define OBJ_FS                      0x0000000d
#define OBJ_FSTREE                  0x0000000e
#define OBJ_STORAGE_MASK            0xc0000000
#define OBJ_EPHEMERAL                0x80000000
#define OBJ_PHYSICAL                 0x40000000

#define CHECKPOINT_MAP_LAST         0x00000001

#define NX_MAGIC 0x4253584e
#define NX_MAX_FILE_SYSTEMS 100

typedef struct nx_superblock {
    obj_phys_t nx_o;
    uint32_t   nx_magic;
    uint32_t   nx_block_size;
    uint64_t   nx_block_count;
    uint64_t   nx_features;
    uint64_t   nx_readonly_compatible_features;
    uint64_t   nx_incompatible_features;
    apfs_uuid_t nx_uuid;
    oid_t      nx_next_oid;
    xid_t      nx_next_xid;
    uint32_t   nx_xp_desc_blocks;
    uint32_t   nx_xp_data_blocks;
    apfs_paddr_t    nx_xp_desc_base;
    apfs_paddr_t    nx_xp_data_base;
    uint32_t   nx_xp_desc_next;
    uint32_t   nx_xp_data_next;
    uint32_t   nx_xp_desc_index;
    uint32_t   nx_xp_desc_len;
    uint32_t   nx_xp_data_index;
    uint32_t   nx_xp_data_len;
    oid_t      nx_spaceman_oid;
    oid_t      nx_omap_oid;
    oid_t      nx_reaper_oid;
    uint32_t   nx_test_type;
    uint32_t   nx_max_file_systems;
    oid_t      nx_fs_oid[NX_MAX_FILE_SYSTEMS];
    uint64_t   nx_counters[NX_NUM_COUNTERS];
    prange_t   nx_blocked_out_prange;
    oid_t      nx_evict_mapping_tree_oid;
    uint64_t   nx_flags;
    apfs_paddr_t nx_efi_jumpstart;
    apfs_uuid_t nx_fusion_uuid;
    prange_t   nx_keylocker;
    uint64_t   nx_ephemeral_info[NX_EPH_INFO_COUNT];
    oid_t      nx_test_oid;
    oid_t      nx_fusion_mt_oid;
    oid_t      nx_fusion_wbc_oid;
    prange_t   nx_fusion_wbc;
    uint64_t   nx_newest_mounted_version;
    prange_t   nx_mkb_locker;
} nx_superblock_t;

#define APFS_SM_DEVICE_COUNT 2

typedef struct spaceman_device {
    uint64_t sm_block_count;
    uint64_t sm_chunk_count;
    uint32_t sm_cib_count;
    uint32_t sm_cab_count;
    uint64_t sm_free_count;
    uint32_t sm_addr_offset;
    uint32_t sm_reserved;
    uint64_t sm_reserved2;
} __attribute__((packed)) spaceman_device_t;

typedef struct spaceman_free_queue {
    uint64_t sfq_count;
    oid_t    sfq_tree_oid;
    xid_t    sfq_oldest_xid;
    uint16_t sfq_tree_node_limit;
    uint16_t sfq_pad16;
    uint32_t sfq_pad32;
    uint64_t sfq_reserved;
} __attribute__((packed)) spaceman_free_queue_t;

typedef struct spaceman_phys {
    obj_phys_t o;
    uint32_t sm_block_size;
    uint32_t sm_blocks_per_chunk;
    uint32_t sm_chunks_per_cib;
    uint32_t sm_cibs_per_cab;
    spaceman_device_t sm_dev[APFS_SM_DEVICE_COUNT];
    uint32_t sm_flags;
    uint32_t sm_ip_bm_tx_multiplier;
    uint64_t sm_ip_block_count;
    uint32_t sm_ip_bm_size_in_blocks;
    uint32_t sm_ip_bm_block_count;
    apfs_paddr_t sm_ip_bm_base;
    apfs_paddr_t sm_ip_base;
    uint64_t sm_fs_reserve_block_count;
    uint64_t sm_fs_reserve_alloc_count;
    spaceman_free_queue_t sm_fq[3];
    uint16_t sm_ip_bm_free_head;
    uint16_t sm_ip_bm_free_tail;
    uint32_t sm_ip_bm_xid_offset;
    uint32_t sm_ip_bitmap_offset;
    uint32_t sm_ip_bm_free_next_offset;
    uint32_t sm_version;
    uint32_t sm_struct_size;
} __attribute__((packed)) spaceman_phys_t;

typedef struct chunk_info_phys {
    uint64_t ci_xid;
    uint64_t ci_addr;
    uint32_t ci_block_count;
    uint32_t ci_free_count;
    apfs_paddr_t ci_bitmap_addr;
} __attribute__((packed)) chunk_info_phys_t;

typedef struct chunk_info_block_phys {
    obj_phys_t cib_o;
    uint32_t cib_index;
    uint32_t cib_chunk_info_count;
    chunk_info_phys_t cib_chunk_info[0];
} __attribute__((packed)) chunk_info_block_phys_t;

typedef struct checkpoint_mapping {
    uint32_t   cpm_type;
    uint32_t   cpm_subtype;
    uint32_t   cpm_size;
    uint32_t   cpm_pad;
    oid_t      cpm_fs_oid;
    oid_t      cpm_oid;
    apfs_paddr_t cpm_paddr;
} checkpoint_mapping_t;

typedef struct checkpoint_map_phys {
    obj_phys_t cpm_o;
    uint32_t   cpm_flags;
    uint32_t   cpm_count;
    checkpoint_mapping_t cpm_map[0];
} checkpoint_map_phys_t;

struct apfsmount {
    nx_superblock_t am_nx;
    uint32_t        am_block_size;
    uint32_t        am_desc_blocks;
    xid_t           am_checkpoint_xid;
};

struct buf {
    void *b_data;
    size_t b_bcount;
};

static int test_fd = -1;
static uint64_t test_file_size = 0;
static uint8_t *synthetic_buffer = NULL;
static size_t synthetic_buffer_size = 0;

int
apfs_bread(struct apfsmount *amp, apfs_paddr_t paddr, struct buf **bpp)
{
    off_t offset;
    ssize_t n;
    struct buf *bp;

    if (paddr < 0 || amp->am_block_size == 0)
        return EINVAL;

    offset = (off_t)paddr * amp->am_block_size;

    bp = calloc(1, sizeof(*bp));
    if (bp == NULL)
        return ENOMEM;

    bp->b_bcount = amp->am_block_size;
    bp->b_data = calloc(1, amp->am_block_size);
    if (bp->b_data == NULL) {
        free(bp);
        return ENOMEM;
    }

    if (synthetic_buffer != NULL) {
        if ((size_t)offset + amp->am_block_size > synthetic_buffer_size) {
            free(bp->b_data);
            free(bp);
            return EOVERFLOW;
        }
        memcpy(bp->b_data, synthetic_buffer + offset, amp->am_block_size);
    } else {
        if ((uint64_t)offset + amp->am_block_size > test_file_size) {
            free(bp->b_data);
            free(bp);
            return EOVERFLOW;
        }
        n = pread(test_fd, bp->b_data, amp->am_block_size, offset);
        if (n != (ssize_t)amp->am_block_size) {
            free(bp->b_data);
            free(bp);
            return (n < 0) ? errno : EIO;
        }
    }

    *bpp = bp;
    return 0;
}

void
brelse(struct buf *bp, int set)
{
    if (bp == NULL)
        return;
    if (bp->b_data != NULL)
        free(bp->b_data);
    free(bp);
}

uint64_t
apfs_fletcher64(const void *buf, size_t len)
{
    const uint32_t *data = buf;
    uint64_t sum1 = 0, sum2 = 0, c1, c2;
    size_t count = len / 4;

    /* Skip the first 8 bytes (checksum itself) */
    data += 2;
    count -= 2;

    for (size_t i = 0; i < count; i++) {
        sum1 += le32toh(data[i]);
        sum2 += sum1;
    }

    c1 = UINT32_MAX - ((sum1 + sum2) % UINT32_MAX);
    c2 = UINT32_MAX - ((sum1 + c1) % UINT32_MAX);

    return (c2 << 32) | c1;
}

bool
apfs_checksum_valid(struct apfsmount *amp, const void *object)
{
    const obj_phys_t *o = object;
    uint64_t stored;

    memcpy(&stored, o->o_cksum, sizeof(stored));
    return apfs_fletcher64(object, amp->am_block_size) == le64toh(stored);
}

#ifndef howmany
#define howmany(x, y) (((x) + ((y) - 1)) / (y))
#endif

static bool
apfs_checkpoint_maps_valid(struct apfsmount *amp,
    const nx_superblock_t *candidate, uint32_t desc_blocks,
    uint32_t desc_slot, xid_t xid)
{
    struct buf *bp;
    checkpoint_map_phys_t *map;
    uint64_t desc_base, block_count;
    uint32_t desc_index, desc_len, capacity, count, flags, i;
    bool found_map = false, found_last = false;

    desc_base = le64toh(candidate->nx_xp_desc_base);
    desc_index = le32toh(candidate->nx_xp_desc_index);
    desc_len = le32toh(candidate->nx_xp_desc_len);
    block_count = le64toh(candidate->nx_block_count);

    if (desc_blocks == 0 || desc_index >= desc_blocks ||
        desc_len == 0 ||
        desc_len > desc_blocks || desc_base >= block_count ||
        desc_base > INT64_MAX || block_count > INT64_MAX ||
        desc_blocks > block_count - desc_base) {
        return false;
    }
    if (((uint64_t)desc_index + desc_len - 1) % desc_blocks != desc_slot) {
        return false;
    }

    capacity = (amp->am_block_size - sizeof(*map)) / sizeof(checkpoint_mapping_t);
    for (i = 0; i < desc_len; i++) {
        uint32_t index = ((uint64_t)desc_index + i) % desc_blocks;
        apfs_paddr_t paddr = (apfs_paddr_t)(desc_base + index);
        int error = apfs_bread(amp, paddr, &bp);
        if (error != 0)
            return false;

        map = (checkpoint_map_phys_t *)bp->b_data;
        if ((le32toh(map->cpm_o.o_type) & OBJECT_TYPE_MASK) != OBJ_CHECKPOINT_MAP ||
            le64toh(map->cpm_o.o_xid) != xid) {
            brelse(bp, 0);
            continue;
        }
        if (le64toh(map->cpm_o.o_oid) != (uint64_t)paddr) {
            brelse(bp, 0);
            return false;
        }
        if (!apfs_checksum_valid(amp, map)) {
            brelse(bp, 0);
            return false;
        }

        count = le32toh(map->cpm_count);
        flags = le32toh(map->cpm_flags);
        if (count > capacity) {
            brelse(bp, 0);
            return false;
        }

        for (uint32_t j = 0; j < count; j++) {
            checkpoint_mapping_t *entry = &map->cpm_map[j];
            uint32_t size = le32toh(entry->cpm_size);
            uint64_t oid = le64toh(entry->cpm_oid);
            uint64_t mapping_paddr = le64toh((uint64_t)entry->cpm_paddr);
            uint32_t storage = le32toh(entry->cpm_type) & OBJ_STORAGE_MASK;
            uint64_t blocks;

            if (oid == 0 || size == 0 || storage != OBJ_EPHEMERAL ||
                mapping_paddr >= block_count) {
                brelse(bp, 0);
                return false;
            }
            blocks = howmany(size, amp->am_block_size);
            if (blocks > block_count - mapping_paddr) {
                brelse(bp, 0);
                return false;
            }
        }
        found_map = true;
        found_last |= (flags & CHECKPOINT_MAP_LAST) != 0;
        brelse(bp, 0);
    }

    if (!found_map || !found_last)
        return false;

    return true;
}

int
apfs_select_checkpoint(struct apfsmount *amp)
{
    struct buf *bp;
    nx_superblock_t base, candidate, selected;
    uint64_t desc_base, block_count, selected_xid = 0;
    uint32_t desc_blocks;
    bool found = false;
    int error;

    base = amp->am_nx;
    desc_base = le64toh(base.nx_xp_desc_base);
    block_count = le64toh(base.nx_block_count);
    desc_blocks = le32toh(base.nx_xp_desc_blocks);

    if (desc_blocks == 0 || desc_base > INT64_MAX ||
        block_count > INT64_MAX || desc_base >= block_count ||
        desc_blocks > block_count - desc_base)
        return EINVAL;

    for (uint32_t i = 0; i < desc_blocks; i++) {
        uint64_t xid;
        uint32_t type;
        bool checksum_valid;

        error = apfs_bread(amp, (apfs_paddr_t)(desc_base + i), &bp);
        if (error != 0)
            continue;

        memcpy(&candidate, bp->b_data, sizeof(candidate));
        type = le32toh(candidate.nx_o.o_type) & OBJECT_TYPE_MASK;
        xid = le64toh(candidate.nx_o.o_xid);
        if (type != OBJ_CONTAINER_SUPERBLOCK) {
            brelse(bp, 0);
            continue;
        }
        if (xid <= selected_xid) {
            brelse(bp, 0);
            continue;
        }
        if (le32toh(candidate.nx_magic) != NX_MAGIC) {
            brelse(bp, 0);
            continue;
        }
        if (le32toh(candidate.nx_block_size) != amp->am_block_size) {
            brelse(bp, 0);
            continue;
        }
        checksum_valid = apfs_checksum_valid(amp, bp->b_data);
        if (!checksum_valid) {
            brelse(bp, 0);
            continue;
        }
        brelse(bp, 0);

        if (le32toh(candidate.nx_max_file_systems) > NX_MAX_FILE_SYSTEMS)
            continue;
        if (le64toh(candidate.nx_block_count) != block_count)
            continue;
        if (le64toh(candidate.nx_xp_desc_base) != desc_base)
            continue;
        if (le32toh(candidate.nx_xp_desc_blocks) != desc_blocks)
            continue;

        if (!apfs_checkpoint_maps_valid(amp, &candidate, desc_blocks, i, xid))
            continue;

        selected = candidate;
        selected_xid = xid;
        found = true;
    }

    if (!found)
        return EINVAL;

    amp->am_nx = selected;
    amp->am_desc_blocks = desc_blocks;
    amp->am_checkpoint_xid = selected_xid;
    return 0;
}

int
apfs_checkpoint_lookup(struct apfsmount *amp, oid_t oid, oid_t fs_oid, apfs_paddr_t *paddrp)
{
    struct buf *bp;
    checkpoint_map_phys_t *map;
    uint64_t desc_base, block_count;
    uint32_t desc_index, desc_len, capacity;

    desc_base = le64toh(amp->am_nx.nx_xp_desc_base);
    block_count = le64toh(amp->am_nx.nx_block_count);
    desc_index = le32toh(amp->am_nx.nx_xp_desc_index);
    desc_len = le32toh(amp->am_nx.nx_xp_desc_len);

    if (amp->am_desc_blocks == 0 || desc_index >= amp->am_desc_blocks ||
        desc_len > amp->am_desc_blocks || desc_base >= block_count ||
        amp->am_desc_blocks > block_count - desc_base)
        return EINVAL;

    capacity = (amp->am_block_size - sizeof(*map)) / sizeof(checkpoint_mapping_t);
    for (uint32_t i = 0; i < desc_len; i++) {
        uint32_t index = ((uint64_t)desc_index + i) % amp->am_desc_blocks;
        int error = apfs_bread(amp, (apfs_paddr_t)(desc_base + index), &bp);
        if (error != 0)
            return error;

        map = (checkpoint_map_phys_t *)bp->b_data;
        if ((le32toh(map->cpm_o.o_type) & OBJECT_TYPE_MASK) != OBJ_CHECKPOINT_MAP ||
            le64toh(map->cpm_o.o_xid) != amp->am_checkpoint_xid) {
            brelse(bp, 0);
            continue;
        }

        if (!apfs_checksum_valid(amp, map)) {
            brelse(bp, 0);
            return EINVAL;
        }

        uint32_t count = le32toh(map->cpm_count);
        if (count > capacity) {
            brelse(bp, 0);
            return EINVAL;
        }

        for (uint32_t j = 0; j < count; j++) {
            checkpoint_mapping_t *entry = &map->cpm_map[j];
            if (le64toh(entry->cpm_oid) == oid &&
                le64toh(entry->cpm_fs_oid) == fs_oid) {
                *paddrp = (apfs_paddr_t)le64toh((uint64_t)entry->cpm_paddr);
                brelse(bp, 0);
                return 0;
            }
        }
        brelse(bp, 0);
    }
    return ENOENT;
}

static bool
apfs_spaceman_paddr_valid(struct apfsmount *amp, uint64_t paddr)
{
    uint64_t block_count = le64toh(amp->am_nx.nx_block_count);
    return paddr != 0 && paddr < block_count && paddr <= INT64_MAX;
}

/*
 * apfs_validate_spaceman matching sys/fs/apfs/apfs_subr.c
 */
int
apfs_validate_spaceman(struct apfsmount *amp)
{
    struct buf *smbp, *cibp;
    spaceman_phys_t *sm;
    spaceman_device_t *dev;
    uint64_t block_count, chunk_count, expected_cib_count;
    uint64_t total_free = 0;
    uint64_t first_clear_free = 0, first_set_free = 0;
    uint64_t first_clear_bitmap = 0, first_set_bitmap = 0;
    uint64_t first_clear_chunk = 0, first_set_chunk = 0;
    uint32_t first_clear_bit = 0, first_set_bit = 0;
    uint32_t blocks_per_chunk, chunks_per_cib, cib_count, addr_offset;
    uint32_t struct_size;
    int free_bit_value = -1;
    bool have_clear_candidate = false, have_set_candidate = false;
    bool have_bitmap = false, have_unmapped_chunk = false;
    apfs_paddr_t spaceman_paddr;
    int error;

    if (le64toh(amp->am_nx.nx_spaceman_oid) == 0)
        return EINVAL;

    error = apfs_checkpoint_lookup(amp,
        le64toh(amp->am_nx.nx_spaceman_oid), 0, &spaceman_paddr);
    if (error != 0) {
        printf("apfs_spaceman: checkpoint lookup for OID 0x%llx failed: error %d\n",
            (unsigned long long)le64toh(amp->am_nx.nx_spaceman_oid), error);
        return error;
    }

    if (!apfs_spaceman_paddr_valid(amp, spaceman_paddr)) {
        printf("apfs_spaceman: OID 0x%llx maps outside the container (block %lld)\n",
            (unsigned long long)le64toh(amp->am_nx.nx_spaceman_oid), (long long)spaceman_paddr);
        return EINVAL;
    }

    error = apfs_bread(amp, spaceman_paddr, &smbp);
    if (error != 0) {
        printf("apfs_spaceman: cannot read object at block %lld: error %d\n",
            (long long)spaceman_paddr, error);
        return error;
    }

    sm = (spaceman_phys_t *)smbp->b_data;
    if (!apfs_checksum_valid(amp, sm) ||
        le64toh(sm->o.o_oid) != le64toh(amp->am_nx.nx_spaceman_oid) ||
        le64toh(sm->o.o_xid) > amp->am_checkpoint_xid ||
        (le32toh(sm->o.o_type) & OBJECT_TYPE_MASK) != OBJ_SPACEMAN) {
        printf("apfs_spaceman: invalid object header at block %lld\n", (long long)spaceman_paddr);
        brelse(smbp, 0);
        return EINVAL;
    }

    blocks_per_chunk = le32toh(sm->sm_blocks_per_chunk);
    chunks_per_cib = le32toh(sm->sm_chunks_per_cib);
    struct_size = le32toh(sm->sm_struct_size);
    dev = &sm->sm_dev[0];
    block_count = le64toh(dev->sm_block_count);
    chunk_count = le64toh(dev->sm_chunk_count);
    cib_count = le32toh(dev->sm_cib_count);
    addr_offset = le32toh(dev->sm_addr_offset);

    if (le32toh(sm->sm_block_size) != amp->am_block_size ||
        blocks_per_chunk == 0 || chunks_per_cib == 0 ||
        struct_size < sizeof(*sm) || struct_size > amp->am_block_size ||
        block_count != le64toh(amp->am_nx.nx_block_count) ||
        chunk_count == 0 || cib_count == 0) {
        printf("apfs_spaceman: invalid geometry\n");
        brelse(smbp, 0);
        return EINVAL;
    }

    if (le32toh(dev->sm_cab_count) != 0 ||
        le64toh(sm->sm_dev[1].sm_block_count) != 0 ||
        le64toh(sm->sm_dev[1].sm_chunk_count) != 0 ||
        le32toh(sm->sm_dev[1].sm_cib_count) != 0 ||
        le32toh(sm->sm_dev[1].sm_cab_count) != 0) {
        printf("apfs_spaceman: CAB or secondary-device layout is not supported\n");
        brelse(smbp, 0);
        return EOPNOTSUPP;
    }

    if (blocks_per_chunk > amp->am_block_size * 8U ||
        chunks_per_cib > (amp->am_block_size - sizeof(chunk_info_block_phys_t)) / sizeof(chunk_info_phys_t) ||
        addr_offset < sizeof(*sm) || addr_offset > amp->am_block_size ||
        cib_count > (amp->am_block_size - addr_offset) / sizeof(uint64_t)) {
        printf("apfs_spaceman: invalid bitmap/CIB layout (blocks/chunk %u, max %u; chunks/cib %u, max %lu; addr_offset %u, sizeof(sm) %lu, block_size %u; cib_count %u, max %lu)\n",
            blocks_per_chunk, amp->am_block_size * 8U,
            chunks_per_cib, (amp->am_block_size - sizeof(chunk_info_block_phys_t)) / sizeof(chunk_info_phys_t),
            addr_offset, sizeof(*sm), amp->am_block_size,
            cib_count, (amp->am_block_size - addr_offset) / sizeof(uint64_t));
        brelse(smbp, 0);
        return EINVAL;
    }

    expected_cib_count = chunk_count / chunks_per_cib + (chunk_count % chunks_per_cib != 0);
    if (chunk_count != block_count / blocks_per_chunk + (block_count % blocks_per_chunk != 0) ||
        expected_cib_count != cib_count) {
        printf("apfs_spaceman: chunk geometry mismatch\n");
        brelse(smbp, 0);
        return EINVAL;
    }

    printf("apfs_spaceman: oid 0x%llx block size %u blocks %llu chunks %llu blocks/chunk %u CIBs %u chunks/CIB %u\n",
        (unsigned long long)le64toh(amp->am_nx.nx_spaceman_oid),
        le32toh(sm->sm_block_size), (unsigned long long)block_count,
        (unsigned long long)chunk_count, blocks_per_chunk, cib_count, chunks_per_cib);

    for (uint32_t i = 0; i < cib_count; i++) {
        uint64_t cib_paddr_le, cib_paddr;
        uint64_t first_chunk = (uint64_t)i * chunks_per_cib;
        uint64_t remaining_chunks = chunk_count - first_chunk;
        uint32_t expected_chunks = (uint32_t)MIN(remaining_chunks, chunks_per_cib);
        chunk_info_block_phys_t *cib;

        memcpy(&cib_paddr_le, (uint8_t *)sm + addr_offset + (size_t)i * sizeof(cib_paddr_le), sizeof(cib_paddr_le));
        cib_paddr = le64toh(cib_paddr_le);

        if (!apfs_spaceman_paddr_valid(amp, cib_paddr)) {
            printf("apfs_spaceman: CIB %u has invalid block address %llu\n", i, (unsigned long long)cib_paddr);
            brelse(smbp, 0);
            return EINVAL;
        }

        error = apfs_bread(amp, (apfs_paddr_t)cib_paddr, &cibp);
        if (error != 0) {
            printf("apfs_spaceman: cannot read CIB %u: error %d\n", i, error);
            brelse(smbp, 0);
            return error;
        }

        cib = (chunk_info_block_phys_t *)cibp->b_data;
        if (!apfs_checksum_valid(amp, cib) ||
            le64toh(cib->cib_o.o_oid) != cib_paddr ||
            le64toh(cib->cib_o.o_xid) > amp->am_checkpoint_xid ||
            (le32toh(cib->cib_o.o_type) & OBJECT_TYPE_MASK) != OBJ_SPACEMAN_CIB ||
            le32toh(cib->cib_index) != i ||
            le32toh(cib->cib_chunk_info_count) != expected_chunks) {
            printf("apfs_spaceman: invalid CIB %u\n", i);
            brelse(cibp, 0);
            brelse(smbp, 0);
            return EINVAL;
        }

        for (uint32_t j = 0; j < expected_chunks; j++) {
            chunk_info_phys_t ci;
            uint64_t chunk_index = first_chunk + j;
            uint64_t chunk_start = chunk_index * blocks_per_chunk;
            uint64_t blocks_remaining = block_count - chunk_start;
            uint32_t expected_blocks = (uint32_t)MIN(blocks_remaining, blocks_per_chunk);
            uint32_t ci_block_count, ci_free_count;
            uint64_t bitmap_paddr;
            uint32_t free_blocks = 0;
            struct buf *bitmap_bp;

            memcpy(&ci, &cib->cib_chunk_info[j], sizeof(ci));
            ci_block_count = le32toh(ci.ci_block_count);
            ci_free_count = le32toh(ci.ci_free_count);
            bitmap_paddr = le64toh((uint64_t)ci.ci_bitmap_addr);

            if (le64toh(ci.ci_xid) > amp->am_checkpoint_xid ||
                le64toh(ci.ci_addr) != chunk_start ||
                ci_block_count != expected_blocks ||
                ci_free_count > expected_blocks) {
                printf("apfs_spaceman: invalid chunk %llu\n", (unsigned long long)chunk_index);
                brelse(cibp, 0);
                brelse(smbp, 0);
                return EINVAL;
            }

            if (bitmap_paddr == 0) {
                if (ci_free_count != expected_blocks) {
                    printf("apfs_spaceman: chunk %llu has no bitmap but reports %u/%u free\n",
                        (unsigned long long)chunk_index, ci_free_count, expected_blocks);
                    brelse(cibp, 0);
                    brelse(smbp, 0);
                    return EINVAL;
                }
                free_blocks = expected_blocks;
                have_unmapped_chunk = true;
            } else {
                if (!apfs_spaceman_paddr_valid(amp, bitmap_paddr) || bitmap_paddr == cib_paddr) {
                    printf("apfs_spaceman: chunk %llu has invalid bitmap block %llu\n",
                        (unsigned long long)chunk_index, (unsigned long long)bitmap_paddr);
                    brelse(cibp, 0);
                    brelse(smbp, 0);
                    return EINVAL;
                }

                error = apfs_bread(amp, (apfs_paddr_t)bitmap_paddr, &bitmap_bp);
                if (error != 0) {
                    printf("apfs_spaceman: cannot read bitmap for chunk %llu: error %d\n",
                        (unsigned long long)chunk_index, error);
                    brelse(cibp, 0);
                    brelse(smbp, 0);
                    return error;
                }

                const uint8_t *bitmap = (const uint8_t *)bitmap_bp->b_data;
                uint32_t clear_blocks = 0, set_blocks = 0;
                uint32_t first_clear = expected_blocks;
                uint32_t first_set = expected_blocks;

                have_bitmap = true;
                for (uint32_t bit = 0; bit < expected_blocks; bit++) {
                    if ((bitmap[bit >> 3] & (1U << (bit & 7))) == 0) {
                        if (first_clear == expected_blocks)
                            first_clear = bit;
                        clear_blocks++;
                    } else {
                        if (first_set == expected_blocks)
                            first_set = bit;
                        set_blocks++;
                    }
                }
                brelse(bitmap_bp, 0);

                if (first_clear < expected_blocks && !have_clear_candidate) {
                    first_clear_free = chunk_start + first_clear;
                    first_clear_bitmap = bitmap_paddr;
                    first_clear_chunk = chunk_index;
                    first_clear_bit = first_clear;
                    have_clear_candidate = true;
                }
                if (first_set < expected_blocks && !have_set_candidate) {
                    first_set_free = chunk_start + first_set;
                    first_set_bitmap = bitmap_paddr;
                    first_set_chunk = chunk_index;
                    first_set_bit = first_set;
                    have_set_candidate = true;
                }

                if (clear_blocks == ci_free_count && set_blocks != ci_free_count) {
                    if (free_bit_value == 1) {
                        printf("apfs_spaceman: bitmap polarity conflicts at chunk %llu\n",
                            (unsigned long long)chunk_index);
                        brelse(cibp, 0);
                        brelse(smbp, 0);
                        return EINVAL;
                    }
                    free_bit_value = 0;
                } else if (set_blocks == ci_free_count && clear_blocks != ci_free_count) {
                    if (free_bit_value == 0) {
                        printf("apfs_spaceman: bitmap polarity conflicts at chunk %llu\n",
                            (unsigned long long)chunk_index);
                        brelse(cibp, 0);
                        brelse(smbp, 0);
                        return EINVAL;
                    }
                    free_bit_value = 1;
                } else if (clear_blocks != ci_free_count || set_blocks != ci_free_count) {
                    printf("apfs_spaceman: chunk %llu bitmap counts clear=%u set=%u disagree with CIB free count %u\n",
                        (unsigned long long)chunk_index, clear_blocks, set_blocks, ci_free_count);
                    brelse(cibp, 0);
                    brelse(smbp, 0);
                    return EINVAL;
                }
                free_blocks = ci_free_count;
            }
            total_free += free_blocks;
        }
        brelse(cibp, 0);
    }

    if (total_free != le64toh(dev->sm_free_count)) {
        printf("apfs_spaceman: chunk free total %llu disagrees with device free count %llu\n",
            (unsigned long long)total_free, (unsigned long long)le64toh(dev->sm_free_count));
        brelse(smbp, 0);
        return EINVAL;
    }

    printf("apfs_spaceman: validated %llu free blocks across %llu chunks\n",
        (unsigned long long)total_free, (unsigned long long)chunk_count);

    if (free_bit_value == 0 && have_clear_candidate) {
        printf("apfs_spaceman: bitmap semantics: clear bits are free; read-only candidate %llu (chunk %llu, bitmap %llu, bit %u; not reserved)\n",
            (unsigned long long)first_clear_free,
            (unsigned long long)first_clear_chunk,
            (unsigned long long)first_clear_bitmap, first_clear_bit);
    } else if (free_bit_value == 1 && have_set_candidate) {
        printf("apfs_spaceman: bitmap semantics: set bits are free; read-only candidate %llu (chunk %llu, bitmap %llu, bit %u; not reserved)\n",
            (unsigned long long)first_set_free,
            (unsigned long long)first_set_chunk,
            (unsigned long long)first_set_bitmap, first_set_bit);
    } else if (total_free == 0) {
        printf("apfs_spaceman: no free-block candidate found\n");
    } else if (have_bitmap) {
        printf("apfs_spaceman: free counts validate, but bitmap polarity is ambiguous; no candidate reported\n");
    } else if (have_unmapped_chunk) {
        printf("apfs_spaceman: free chunks lack allocation bitmaps; no safe candidate reported\n");
    }

    brelse(smbp, 0);
    return 0;
}

static int
init_mount(const char *image_path, struct apfsmount *amp)
{
    struct stat st;
    struct buf *bp;
    nx_superblock_t *nx;
    int error;

    test_fd = open(image_path, O_RDONLY);
    if (test_fd < 0) {
        perror("open image");
        return errno;
    }

    if (fstat(test_fd, &st) < 0) {
        close(test_fd);
        return errno;
    }
    test_file_size = (uint64_t)st.st_size;

    memset(amp, 0, sizeof(*amp));
    amp->am_block_size = 4096;

    error = apfs_bread(amp, 0, &bp);
    if (error != 0) {
        close(test_fd);
        return error;
    }

    nx = (nx_superblock_t *)bp->b_data;
    amp->am_block_size = le32toh(nx->nx_block_size);
    memcpy(&amp->am_nx, nx, sizeof(*nx));
    brelse(bp, 0);

    error = apfs_select_checkpoint(amp);
    if (error != 0) {
        printf("apfs_select_checkpoint failed: %d\n", error);
        close(test_fd);
        return error;
    }

    return 0;
}

static void
cleanup_mount(struct apfsmount *amp)
{
    if (test_fd >= 0) {
        close(test_fd);
        test_fd = -1;
    }
}

static void
recalculate_checksum(void *block, uint32_t block_size)
{
    obj_phys_t *obj = block;
    uint64_t cksum;

    memset(obj->o_cksum, 0, sizeof(obj->o_cksum));
    cksum = apfs_fletcher64(block, block_size);
    cksum = htole64(cksum);
    memcpy(obj->o_cksum, &cksum, sizeof(cksum));
}

static int
run_synthetic_test(void (*modify_fn)(uint8_t *buf, size_t size, struct apfsmount *amp))
{
    struct apfsmount amp;
    int error;

    /* Base synthetic buffer cloned from fresh 50M image */
    int fd = open("/tmp/apfs_test_images/fresh_50m.dmg", O_RDONLY);
    if (fd < 0)
        return -1;
    struct stat st;
    fstat(fd, &st);
    synthetic_buffer_size = st.st_size;
    synthetic_buffer = malloc(synthetic_buffer_size);
    if (pread(fd, synthetic_buffer, synthetic_buffer_size, 0) != (ssize_t)synthetic_buffer_size) {
        close(fd);
        free(synthetic_buffer);
        synthetic_buffer = NULL;
        return -1;
    }
    close(fd);

    memset(&amp, 0, sizeof(amp));
    amp.am_block_size = 4096;
    nx_superblock_t *nx = (nx_superblock_t *)synthetic_buffer;
    amp.am_block_size = le32toh(nx->nx_block_size);
    memcpy(&amp.am_nx, nx, sizeof(*nx));

    error = apfs_select_checkpoint(&amp);
    if (error != 0) {
        free(synthetic_buffer);
        synthetic_buffer = NULL;
        return error;
    }

    /* Apply modification callback */
    modify_fn(synthetic_buffer, synthetic_buffer_size, &amp);

    error = apfs_validate_spaceman(&amp);

    free(synthetic_buffer);
    synthetic_buffer = NULL;
    return error;
}

static void
mod_unmapped_chunk(uint8_t *buf, size_t size __unused, struct apfsmount *amp)
{
    /* Locate CIB and set ci_bitmap_addr = 0 */
    apfs_paddr_t sm_paddr;
    apfs_checkpoint_lookup(amp, le64toh(amp->am_nx.nx_spaceman_oid), 0, &sm_paddr);
    spaceman_phys_t *sm = (spaceman_phys_t *)(buf + sm_paddr * amp->am_block_size);
    uint32_t addr_offset = le32toh(sm->sm_dev[0].sm_addr_offset);
    uint64_t cib_paddr = le64toh(*(uint64_t *)((uint8_t *)sm + addr_offset));

    chunk_info_block_phys_t *cib = (chunk_info_block_phys_t *)(buf + cib_paddr * amp->am_block_size);
    cib->cib_chunk_info[0].ci_bitmap_addr = 0;
    cib->cib_chunk_info[0].ci_free_count = cib->cib_chunk_info[0].ci_block_count;
    recalculate_checksum(cib, amp->am_block_size);

    sm->sm_dev[0].sm_free_count = cib->cib_chunk_info[0].ci_block_count;
    recalculate_checksum(sm, amp->am_block_size);
}

static void
mod_corrupt_cib_checksum(uint8_t *buf, size_t size __unused, struct apfsmount *amp)
{
    apfs_paddr_t sm_paddr;
    apfs_checkpoint_lookup(amp, le64toh(amp->am_nx.nx_spaceman_oid), 0, &sm_paddr);
    spaceman_phys_t *sm = (spaceman_phys_t *)(buf + sm_paddr * amp->am_block_size);
    uint32_t addr_offset = le32toh(sm->sm_dev[0].sm_addr_offset);
    uint64_t cib_paddr = le64toh(*(uint64_t *)((uint8_t *)sm + addr_offset));

    /* Corrupt byte in CIB without updating checksum */
    buf[cib_paddr * amp->am_block_size + 45] ^= 0xff;
}

static void
mod_out_of_bounds_cib(uint8_t *buf, size_t size __unused, struct apfsmount *amp)
{
    apfs_paddr_t sm_paddr;
    apfs_checkpoint_lookup(amp, le64toh(amp->am_nx.nx_spaceman_oid), 0, &sm_paddr);
    spaceman_phys_t *sm = (spaceman_phys_t *)(buf + sm_paddr * amp->am_block_size);
    uint32_t addr_offset = le32toh(sm->sm_dev[0].sm_addr_offset);

    /* Point CIB outside container */
    uint64_t bad_addr = htole64(le64toh(amp->am_nx.nx_block_count) + 500);
    memcpy((uint8_t *)sm + addr_offset, &bad_addr, sizeof(bad_addr));
    recalculate_checksum(sm, amp->am_block_size);
}

static void
mod_unsupported_cab(uint8_t *buf, size_t size __unused, struct apfsmount *amp)
{
    apfs_paddr_t sm_paddr;
    apfs_checkpoint_lookup(amp, le64toh(amp->am_nx.nx_spaceman_oid), 0, &sm_paddr);
    spaceman_phys_t *sm = (spaceman_phys_t *)(buf + sm_paddr * amp->am_block_size);
    sm->sm_dev[0].sm_cab_count = htole32(1);
    recalculate_checksum(sm, amp->am_block_size);
}

static void
mod_unsupported_secondary_device(uint8_t *buf, size_t size __unused, struct apfsmount *amp)
{
    apfs_paddr_t sm_paddr;
    apfs_checkpoint_lookup(amp, le64toh(amp->am_nx.nx_spaceman_oid), 0, &sm_paddr);
    spaceman_phys_t *sm = (spaceman_phys_t *)(buf + sm_paddr * amp->am_block_size);
    sm->sm_dev[1].sm_block_count = htole64(1000);
    recalculate_checksum(sm, amp->am_block_size);
}

int
main(int argc, char **argv)
{
    struct apfsmount amp;
    int error;

    if (argc > 1) {
        printf("=== Testing Space Manager on %s ===\n", argv[1]);
        error = init_mount(argv[1], &amp);
        if (error != 0) {
            fprintf(stderr, "FAIL: init_mount returned %d\n", error);
            return 1;
        }

        error = apfs_validate_spaceman(&amp);
        cleanup_mount(&amp);

        if (error != 0) {
            fprintf(stderr, "FAIL: apfs_validate_spaceman returned %d\n", error);
            return 1;
        }

        printf("PASS: Space Manager successfully validated on %s\n", argv[1]);
        return 0;
    }

    printf("=== Running Comprehensive APFS Space Manager Test Suite ===\n");

    /* 1. Real Image Tests */
    const char *test_images[] = {
        "/tmp/apfs_test_images/fresh_50m.dmg",
        "/tmp/apfs_test_images/populated_100m.dmg",
        "/tmp/apfs_test_images/multichunk_300m.dmg"
    };

    for (size_t i = 0; i < sizeof(test_images)/sizeof(test_images[0]); i++) {
        printf("\n--- Test Case: Real APFS Image (%s) ---\n", test_images[i]);
        error = init_mount(test_images[i], &amp);
        assert(error == 0);
        error = apfs_validate_spaceman(&amp);
        assert(error == 0);
        cleanup_mount(&amp);
        printf("PASS: Real image %s passed validation\n", test_images[i]);
    }

    /* 2. Unmapped Chunk Test */
    printf("\n--- Test Case: Unmapped Chunk (ci_bitmap_addr == 0) ---\n");
    error = run_synthetic_test(mod_unmapped_chunk);
    assert(error == 0);
    printf("PASS: Unmapped chunk handled cleanly\n");

    /* 3. Corrupt CIB Checksum Test */
    printf("\n--- Test Case: Corrupt CIB Checksum (Fail-Closed) ---\n");
    error = run_synthetic_test(mod_corrupt_cib_checksum);
    assert(error == EINVAL);
    printf("PASS: Corrupt CIB checksum rejected with EINVAL\n");

    /* 4. Out-of-Bounds CIB Address Test */
    printf("\n--- Test Case: Out-of-Bounds CIB Address (Fail-Closed) ---\n");
    error = run_synthetic_test(mod_out_of_bounds_cib);
    assert(error == EINVAL);
    printf("PASS: Out-of-bounds CIB address rejected with EINVAL\n");

    /* 5. Unsupported CAB Layout Test */
    printf("\n--- Test Case: Unsupported CAB Layout (Fail-Closed) ---\n");
    error = run_synthetic_test(mod_unsupported_cab);
    assert(error == EOPNOTSUPP);
    printf("PASS: CAB layout rejected with EOPNOTSUPP\n");

    /* 6. Unsupported Secondary Device Test */
    printf("\n--- Test Case: Unsupported Secondary Device (Fail-Closed) ---\n");
    error = run_synthetic_test(mod_unsupported_secondary_device);
    assert(error == EOPNOTSUPP);
    printf("PASS: Secondary device layout rejected with EOPNOTSUPP\n");

    printf("\n=======================================================\n");
    printf("ALL APFS SPACE MANAGER TESTS PASSED SUCCESSFULLY (100%%)\n");
    printf("=======================================================\n");
    return 0;
}

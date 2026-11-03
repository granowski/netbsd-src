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
#include <pthread.h>
#include <sys/queue.h>

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

typedef struct apfs_range {
    uint64_t ar_start;
    uint64_t ar_len;
} apfs_range_t;

#define APFS_EXCLUSION_MAX_RANGES 16

typedef struct apfs_exclusion_table {
    apfs_range_t aet_ranges[APFS_EXCLUSION_MAX_RANGES];
    uint32_t     aet_count;
} apfs_exclusion_table_t;

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

#define APFS_BTREE_MAX_DEPTH 16
#define BTNODE_ROOT           0x0001
#define BTNODE_LEAF           0x0002
#define BTNODE_FIXED_KV_SIZE  0x0004
#define BTNODE_HASHED         0x0008
#define BTNODE_NOHEADER       0x0020

#define BTREE_PHYSICAL        0x00000001
#define BTREE_EPHEMERAL       0x00000002
#define BTREE_HASHED          0x00000008

#define APFS_TYPE_ANY         0
#define APFS_TYPE_SNAP_METADATA 1
#define APFS_TYPE_EXTENT      2
#define APFS_TYPE_INODE       3
#define APFS_TYPE_XATTR       4
#define APFS_TYPE_SIBLING     5
#define APFS_TYPE_DIR_REC     6
#define APFS_TYPE_DIR_STATS   7

#define OBJ_ID_MASK           0x0ffffffffffffffULL
#define OBJ_TYPE_SHIFT        60
#define OBJ_TYPE_MASK         0xf000000000000000ULL

#define DREC_HASH_SHIFT       10
#define DREC_NLEN_MASK        0x03ff
#define J_EXT_LEN_MASK        0x00ffffffffffffffULL

typedef struct btree_node_phys {
    obj_phys_t btn_o;
    uint16_t   btn_flags;
    uint16_t   btn_level;
    uint32_t   btn_nkeys;
    uint16_t   btn_table_space_off;
    uint16_t   btn_table_space_len;
    uint16_t   btn_free_space_off;
    uint16_t   btn_free_space_len;
    uint16_t   btn_key_free_list_len;
    uint16_t   btn_val_free_list_len;
    uint8_t    btn_data[0];
} __attribute__((packed)) btree_node_phys_t;

typedef struct btree_info {
    uint32_t bt_flags;
    uint32_t bt_node_size;
    uint32_t bt_key_size;
    uint32_t bt_val_size;
    uint32_t bt_longest_key;
    uint32_t bt_longest_val;
    uint64_t bt_key_count;
    uint64_t bt_node_count;
} __attribute__((packed)) btree_info_t;

typedef struct btree_toc_entry {
    uint16_t key_off;
    uint16_t key_len;
    uint16_t val_off;
    uint16_t val_len;
} __attribute__((packed)) btree_toc_entry_t;

typedef struct btree_toc_fixed_entry {
    uint16_t key_off;
    uint16_t val_off;
} __attribute__((packed)) btree_toc_fixed_entry_t;

typedef struct apfs_btree_path_entry {
    apfs_paddr_t    pe_paddr;
    uint32_t        pe_idx;
    uint32_t        pe_flags;
} apfs_btree_path_entry_t;

typedef struct apfs_btree_path {
    uint32_t                bp_depth;
    apfs_btree_path_entry_t bp_entries[APFS_BTREE_MAX_DEPTH];
} apfs_btree_path_t;

typedef struct j_key {
    uint64_t obj_id_and_type;
} __attribute__((packed)) j_key_t;

typedef struct j_inode_val {
    uint64_t parent_id;
    uint64_t private_id;
    uint64_t create_time;
    uint64_t mod_time;
    uint64_t change_time;
    uint64_t access_time;
    uint64_t internal_flags;
    uint32_t nchildren_or_nlink;
    uint32_t default_crypto_id;
    uint32_t bsd_flags;
    uint32_t owner;
    uint32_t group;
    uint16_t mode;
    uint16_t pad1;
    uint64_t uncompressed_size;
} __attribute__((packed)) j_inode_val_t;

typedef struct j_drec_hashed_key {
    j_key_t  hdr;
    uint32_t name_len_and_hash;
    char     name[0];
} __attribute__((packed)) j_drec_hashed_key_t;

typedef struct j_drec_val {
    uint64_t file_id;
    uint64_t date_added;
    uint16_t flags;
} __attribute__((packed)) j_drec_val_t;

typedef struct j_extent_key {
    j_key_t  hdr;
    uint64_t logical_addr;
} __attribute__((packed)) j_extent_key_t;

typedef struct j_phys_ext_val {
    uint64_t len_and_flags;
    uint64_t phys_block_num;
    uint64_t crypto_id;
} __attribute__((packed)) j_phys_ext_val_t;

typedef struct apfs_crypto_state {
    uint16_t major_version;
    uint16_t minor_version;
    uint32_t cpflags;
    uint32_t persistent_class;
    uint32_t key_os_version;
    uint16_t key_revision;
    uint16_t unused;
} apfs_crypto_state_t;

typedef struct apfs_superblock {
    obj_phys_t apfs_o;
    uint32_t   apfs_magic;
    uint32_t   apfs_fs_index;
    uint64_t   apfs_features;
    uint64_t   apfs_readonly_compatible_features;
    uint64_t   apfs_incompatible_features;
    uint64_t   apfs_unmount_time;
    uint64_t   apfs_fs_reserve_block_count;
    uint64_t   apfs_fs_quota_block_count;
    uint64_t   apfs_fs_alloc_count;
    apfs_crypto_state_t apfs_meta_crypto;
    uint32_t   apfs_root_tree_type;
    uint32_t   apfs_extentref_tree_type;
    uint32_t   apfs_snap_meta_tree_type;
    oid_t      apfs_omap_oid;
    oid_t      apfs_root_tree_oid;
    oid_t      apfs_extentref_tree_oid;
    oid_t      apfs_snap_meta_tree_oid;
    xid_t      apfs_revert_to_xid;
    oid_t      apfs_revert_to_sblock_oid;
    uint64_t   apfs_next_obj_id;
    uint64_t   apfs_num_files;
    uint64_t   apfs_num_directories;
    uint64_t   apfs_num_symlinks;
    uint64_t   apfs_num_other_fsobjects;
    uint64_t   apfs_num_snapshots;
    uint64_t   apfs_total_blocks_alloced;
    uint64_t   apfs_total_blocks_freed;
    apfs_uuid_t apfs_vol_uuid;
    uint64_t   apfs_last_mod_time;
    uint64_t   apfs_fs_flags;
    uint8_t    apfs_formatted_by[32 + 8 + 8];
    uint8_t    apfs_modified_by[APFS_MAX_HIST * (32 + 8 + 8)];
    uint8_t    apfs_volname[APFS_VOLNAME_LEN];
    uint32_t   apfs_next_doc_id;
    uint16_t   apfs_role;
    uint16_t   apfs_reserved;
    xid_t      apfs_root_to_xid;
    oid_t      apfs_er_state_oid;
    uint64_t   apfs_cloneinfo_id_epoch;
    uint64_t   apfs_cloneinfo_xid;
    oid_t      apfs_snap_meta_ext_oid;
    apfs_uuid_t apfs_volume_group_id;
    oid_t      apfs_integrity_meta_oid;
    oid_t      apfs_fext_tree_oid;
    uint32_t   apfs_fext_tree_type;
    uint32_t   apfs_reserved_type;
    oid_t      apfs_reserved_oid;
} apfs_superblock_t;

typedef pthread_mutex_t kmutex_t;
#define IPL_NONE 0
#define MUTEX_DEFAULT 0
#define mutex_init(m, a, b) pthread_mutex_init(m, NULL)
#define mutex_destroy(m) pthread_mutex_destroy(m)
#define mutex_enter(m) pthread_mutex_lock(m)
#define mutex_exit(m) pthread_mutex_unlock(m)
#define KM_SLEEP 0
#define kmem_zalloc(s, f) calloc(1, s)
#define kmem_free(p, s) free(p)

/* In-memory block reservation span */
typedef struct apfs_resv_entry {
    uint64_t                re_paddr;
    uint64_t                re_block_count;
    uint64_t                re_tx_id;
    LIST_ENTRY(apfs_resv_entry) re_link;
} apfs_resv_entry_t;

/* Global reservation pool in apfsmount */
typedef struct apfs_resv_pool {
    kmutex_t                rp_lock;
    uint64_t                rp_total_reserved;
    uint64_t                rp_last_chunk;
    uint32_t                rp_last_bit;
    LIST_HEAD(apfs_resv_head, apfs_resv_entry) rp_entries;
} apfs_resv_pool_t;

/* Per-transaction reservation handle */
typedef struct apfs_resv_tx {
    uint64_t                rt_tx_id;
    uint64_t                rt_count;
    LIST_HEAD(apfs_resv_tx_head, apfs_resv_entry) rt_entries;
} apfs_resv_tx_t;

/* Transaction States */
typedef enum {
    APFS_TX_STATE_INACTIVE = 0,
    APFS_TX_STATE_ACTIVE,
    APFS_TX_STATE_COMMITTING,
    APFS_TX_STATE_COMMITTED,
    APFS_TX_STATE_ABORTED
} apfs_tx_state_t;

/* Maximum ephemeral mappings per checkpoint transaction */
#define APFS_TX_MAX_MAPPINGS 128

/* In-memory Transaction Context */
typedef struct apfs_tx {
    struct apfsmount       *tx_amp;
    uint64_t                tx_xid;
    apfs_tx_state_t         tx_state;
    apfs_resv_tx_t          tx_resv;
    uint32_t                tx_map_count;
    checkpoint_mapping_t    tx_mappings[APFS_TX_MAX_MAPPINGS];
} apfs_tx_t;

struct apfsmount {
    nx_superblock_t am_nx;
    uint32_t        am_block_size;
    uint32_t        am_desc_blocks;
    xid_t           am_checkpoint_xid;
    apfs_resv_pool_t am_resv_pool;
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
brelse(struct buf *bp, int set __unused)
{
    if (bp == NULL)
        return;
    if (bp->b_data != NULL)
        free(bp->b_data);
    free(bp);
}

int
apfs_getblk(struct apfsmount *amp, apfs_paddr_t paddr, struct buf **bpp)
{
    struct buf *bp;

    if (paddr < 0 || amp->am_block_size == 0)
        return EINVAL;

    bp = calloc(1, sizeof(*bp));
    if (bp == NULL)
        return ENOMEM;

    bp->b_bcount = amp->am_block_size;
    bp->b_data = calloc(1, amp->am_block_size);
    if (bp->b_data == NULL) {
        free(bp);
        return ENOMEM;
    }

    *bpp = bp;
    return 0;
}

int
apfs_bwrite(struct apfsmount *amp, apfs_paddr_t paddr, struct buf *bp)
{
    off_t offset;
    ssize_t n;

    if (paddr < 0 || amp->am_block_size == 0 || bp == NULL)
        return EINVAL;

    offset = (off_t)paddr * amp->am_block_size;

    if (synthetic_buffer != NULL) {
        if ((size_t)offset + amp->am_block_size > synthetic_buffer_size) {
            brelse(bp, 0);
            return EOVERFLOW;
        }
        memcpy(synthetic_buffer + offset, bp->b_data, amp->am_block_size);
    } else {
        if ((uint64_t)offset + amp->am_block_size > test_file_size) {
            brelse(bp, 0);
            return EOVERFLOW;
        }
        n = pwrite(test_fd, bp->b_data, amp->am_block_size, offset);
        if (n != (ssize_t)amp->am_block_size) {
            brelse(bp, 0);
            return (n < 0) ? errno : EIO;
        }
    }

    brelse(bp, 0);
    return 0;
}

int
apfs_bwrite_cow(apfs_tx_t *tx, apfs_paddr_t paddr, struct buf *bp)
{
    if (tx == NULL || tx->tx_amp == NULL || tx->tx_state != APFS_TX_STATE_ACTIVE)
        return EINVAL;

    return apfs_bwrite(tx->tx_amp, paddr, bp);
}

void
apfs_obj_init(obj_phys_t *obj, oid_t oid, uint64_t xid, uint32_t type,
    uint32_t subtype)
{
    if (obj == NULL)
        return;

    memset(obj->o_cksum, 0, sizeof(obj->o_cksum));
    obj->o_oid = htole64(oid);
    obj->o_xid = htole64(xid);
    obj->o_type = htole32(type);
    obj->o_subtype = htole32(subtype);
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

void
apfs_obj_set_cksum(struct apfsmount *amp, void *obj)
{
    obj_phys_t *o = (obj_phys_t *)obj;
    uint64_t cksum, le_cksum;

    if (amp == NULL || o == NULL)
        return;

    memset(o->o_cksum, 0, sizeof(o->o_cksum));
    cksum = apfs_fletcher64(obj, amp->am_block_size);
    le_cksum = htole64(cksum);
    memcpy(o->o_cksum, &le_cksum, sizeof(o->o_cksum));
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

bool
apfs_range_valid(struct apfsmount *amp, uint64_t start, uint64_t len)
{
    uint64_t block_count = le64toh(amp->am_nx.nx_block_count);

    if (len == 0)
        return true;
    if (start > INT64_MAX || len > INT64_MAX)
        return false;
    if (start + len < start || start + len > block_count)
        return false;
    return true;
}

bool
apfs_range_overlaps(uint64_t s1, uint64_t l1, uint64_t s2, uint64_t l2)
{
    if (l1 == 0 || l2 == 0)
        return false;
    return s1 < (s2 + l2) && s2 < (s1 + l1);
}

int
apfs_exclusion_add(struct apfsmount *amp, apfs_exclusion_table_t *table,
    uint64_t start, uint64_t len, const char *desc)
{
    if (len == 0)
        return 0;

    if (!apfs_range_valid(amp, start, len)) {
        printf("apfs_spaceman: invalid exclusion range for %s "
            "(start %llu, len %llu, container blocks %llu)\n",
            desc, (unsigned long long)start, (unsigned long long)len,
            (unsigned long long)le64toh(amp->am_nx.nx_block_count));
        return EINVAL;
    }

    for (uint32_t i = 0; i < table->aet_count; i++) {
        if (apfs_range_overlaps(start, len,
            table->aet_ranges[i].ar_start,
            table->aet_ranges[i].ar_len)) {
            printf("apfs_spaceman: exclusion range overlap: %s "
                "(%llu..%llu) overlaps with range %u (%llu..%llu)\n",
                desc, (unsigned long long)start,
                (unsigned long long)(start + len - 1), i,
                (unsigned long long)table->aet_ranges[i].ar_start,
                (unsigned long long)(table->aet_ranges[i].ar_start +
                table->aet_ranges[i].ar_len - 1));
            return EINVAL;
        }
    }

    if (table->aet_count >= APFS_EXCLUSION_MAX_RANGES) {
        printf("apfs_spaceman: exclusion table full\n");
        return EINVAL;
    }

    table->aet_ranges[table->aet_count].ar_start = start;
    table->aet_ranges[table->aet_count].ar_len = len;
    table->aet_count++;
    return 0;
}

int
apfs_build_container_exclusions(struct apfsmount *amp,
    apfs_exclusion_table_t *table)
{
    int error;

    memset(table, 0, sizeof(*table));

    /* Block 0: Container Superblock */
    error = apfs_exclusion_add(amp, table, 0, 1, "container superblock");
    if (error != 0)
        return error;

    /* Checkpoint Descriptor Ring */
    error = apfs_exclusion_add(amp, table,
        (uint64_t)le64toh((uint64_t)amp->am_nx.nx_xp_desc_base),
        (uint64_t)le32toh(amp->am_nx.nx_xp_desc_blocks),
        "checkpoint descriptor ring");
    if (error != 0)
        return error;

    /* Checkpoint Data Ring */
    error = apfs_exclusion_add(amp, table,
        (uint64_t)le64toh((uint64_t)amp->am_nx.nx_xp_data_base),
        (uint64_t)le32toh(amp->am_nx.nx_xp_data_blocks),
        "checkpoint data ring");
    if (error != 0)
        return error;

    /* Blocked out prange (if specified) */
    if (le64toh(amp->am_nx.nx_blocked_out_prange.pr_block_count) > 0) {
        error = apfs_exclusion_add(amp, table,
            (uint64_t)le64toh((uint64_t)amp->am_nx.nx_blocked_out_prange.pr_start_paddr),
            le64toh(amp->am_nx.nx_blocked_out_prange.pr_block_count),
            "blocked out prange");
        if (error != 0)
            return error;
    }

    return 0;
}

bool
apfs_spaceman_candidate_safe(struct apfsmount *amp,
    const apfs_exclusion_table_t *table, uint64_t paddr)
{
    if (!apfs_spaceman_paddr_valid(amp, paddr))
        return false;

    if (table != NULL) {
        for (uint32_t i = 0; i < table->aet_count; i++) {
            uint64_t start = table->aet_ranges[i].ar_start;
            uint64_t len = table->aet_ranges[i].ar_len;
            if (paddr >= start && paddr < start + len)
                return false;
        }
    }

    return true;
}

int
apfs_resv_init(struct apfsmount *amp)
{
    mutex_init(&amp->am_resv_pool.rp_lock, MUTEX_DEFAULT, IPL_NONE);
    amp->am_resv_pool.rp_total_reserved = 0;
    amp->am_resv_pool.rp_last_chunk = 0;
    amp->am_resv_pool.rp_last_bit = 0;
    LIST_INIT(&amp->am_resv_pool.rp_entries);
    return 0;
}

void
apfs_resv_destroy(struct apfsmount *amp)
{
    apfs_resv_entry_t *entry, *tmp;

    mutex_enter(&amp->am_resv_pool.rp_lock);
    entry = LIST_FIRST(&amp->am_resv_pool.rp_entries);
    while (entry != NULL) {
        tmp = LIST_NEXT(entry, re_link);
        LIST_REMOVE(entry, re_link);
        kmem_free(entry, sizeof(*entry));
        entry = tmp;
    }
    amp->am_resv_pool.rp_total_reserved = 0;
    mutex_exit(&amp->am_resv_pool.rp_lock);
    mutex_destroy(&amp->am_resv_pool.rp_lock);
}

static bool
apfs_resv_is_reserved_locked(struct apfsmount *amp, uint64_t paddr, uint64_t count)
{
    apfs_resv_entry_t *entry;

    if (count == 0)
        return false;

    LIST_FOREACH(entry, &amp->am_resv_pool.rp_entries, re_link) {
        if (apfs_range_overlaps(paddr, count,
            entry->re_paddr, entry->re_block_count)) {
            return true;
        }
    }
    return false;
}

bool
apfs_resv_is_reserved(struct apfsmount *amp, uint64_t paddr, uint64_t count)
{
    bool reserved;

    mutex_enter(&amp->am_resv_pool.rp_lock);
    reserved = apfs_resv_is_reserved_locked(amp, paddr, count);
    mutex_exit(&amp->am_resv_pool.rp_lock);

    return reserved;
}

int
apfs_resv_alloc(struct apfsmount *amp, apfs_resv_tx_t *tx, uint64_t count,
    apfs_paddr_t *paddrp)
{
    struct buf *smbp = NULL, *cibp = NULL, *bp = NULL;
    spaceman_phys_t *sm;
    spaceman_device_t *dev;
    apfs_exclusion_table_t excl_table;
    uint64_t block_count, chunk_count, ip_block_count;
    uint32_t blocks_per_chunk, chunks_per_cib, cib_count, addr_offset;
    uint32_t ip_bm_block_count;
    apfs_paddr_t spaceman_paddr, ip_base, ip_bm_base;
    const apfs_paddr_t *cib_addrs;
    int error;

    if (count == 0 || paddrp == NULL || count > INT64_MAX)
        return EINVAL;

    *paddrp = 0;

    if (le64toh(amp->am_nx.nx_spaceman_oid) == 0)
        return EINVAL;

    error = apfs_build_container_exclusions(amp, &excl_table);
    if (error != 0)
        return error;

    error = apfs_checkpoint_lookup(amp,
        le64toh(amp->am_nx.nx_spaceman_oid), 0, &spaceman_paddr);
    if (error != 0)
        return error;

    if (!apfs_spaceman_paddr_valid(amp, spaceman_paddr))
        return EINVAL;

    error = apfs_bread(amp, spaceman_paddr, &smbp);
    if (error != 0)
        return error;

    sm = (spaceman_phys_t *)smbp->b_data;
    if (!apfs_checksum_valid(amp, sm) ||
        le64toh(sm->o.o_oid) != le64toh(amp->am_nx.nx_spaceman_oid) ||
        le64toh(sm->o.o_xid) > amp->am_checkpoint_xid ||
        (le32toh(sm->o.o_type) & OBJECT_TYPE_MASK) != OBJ_SPACEMAN) {
        brelse(smbp, 0);
        return EINVAL;
    }

    blocks_per_chunk = le32toh(sm->sm_blocks_per_chunk);
    chunks_per_cib = le32toh(sm->sm_chunks_per_cib);
    dev = &sm->sm_dev[0];
    block_count = le64toh(dev->sm_block_count);
    chunk_count = le64toh(dev->sm_chunk_count);
    cib_count = le32toh(dev->sm_cib_count);
    addr_offset = le32toh(dev->sm_addr_offset);

    if (blocks_per_chunk == 0 || chunks_per_cib == 0 ||
        chunk_count == 0 || cib_count == 0 ||
        addr_offset < sizeof(*sm) || addr_offset > amp->am_block_size ||
        cib_count > (amp->am_block_size - addr_offset) / sizeof(apfs_paddr_t)) {
        brelse(smbp, 0);
        return EINVAL;
    }

    ip_block_count = le64toh(sm->sm_ip_block_count);
    ip_bm_block_count = le32toh(sm->sm_ip_bm_block_count);
    ip_base = (apfs_paddr_t)le64toh((uint64_t)sm->sm_ip_base);
    ip_bm_base = (apfs_paddr_t)le64toh((uint64_t)sm->sm_ip_bm_base);

    if (ip_block_count > 0 &&
        apfs_range_valid(amp, (uint64_t)ip_base, ip_block_count)) {
        (void)apfs_exclusion_add(amp, &excl_table, (uint64_t)ip_base,
            ip_block_count, "internal pool data");
    }
    if (ip_bm_block_count > 0 &&
        apfs_range_valid(amp, (uint64_t)ip_bm_base, (uint64_t)ip_bm_block_count)) {
        (void)apfs_exclusion_add(amp, &excl_table, (uint64_t)ip_bm_base,
            (uint64_t)ip_bm_block_count, "internal pool bitmap");
    }

    cib_addrs = (const apfs_paddr_t *)((const uint8_t *)sm + addr_offset);

    mutex_enter(&amp->am_resv_pool.rp_lock);

    uint64_t start_chunk = amp->am_resv_pool.rp_last_chunk % chunk_count;
    uint32_t start_bit = amp->am_resv_pool.rp_last_bit;
    bool found = false;
    uint64_t found_paddr = 0;

    for (uint64_t c_offset = 0; c_offset < chunk_count && !found; c_offset++) {
        uint64_t chunk_idx = (start_chunk + c_offset) % chunk_count;
        uint32_t cib_idx = chunk_idx / chunks_per_cib;
        uint32_t chunk_in_cib = chunk_idx % chunks_per_cib;

        if (cib_idx >= cib_count)
            continue;

        apfs_paddr_t cib_paddr = (apfs_paddr_t)le64toh((uint64_t)cib_addrs[cib_idx]);
        if (!apfs_spaceman_paddr_valid(amp, (uint64_t)cib_paddr))
            continue;

        error = apfs_bread(amp, cib_paddr, &cibp);
        if (error != 0)
            continue;

        chunk_info_block_phys_t *cib = (chunk_info_block_phys_t *)cibp->b_data;
        if (!apfs_checksum_valid(amp, cib) ||
            (le32toh(cib->cib_o.o_type) & OBJECT_TYPE_MASK) != OBJ_SPACEMAN_CIB) {
            brelse(cibp, 0);
            cibp = NULL;
            continue;
        }

        chunk_info_phys_t *chunk = &cib->cib_chunk_info[chunk_in_cib];
        uint32_t ci_free_count = le32toh(chunk->ci_free_count);
        apfs_paddr_t bitmap_paddr = (apfs_paddr_t)le64toh((uint64_t)chunk->ci_bitmap_addr);
        uint64_t chunk_start = (uint64_t)chunk_idx * blocks_per_chunk;
        uint32_t expected_blocks = (chunk_start + blocks_per_chunk > block_count) ?
            (uint32_t)(block_count - chunk_start) : blocks_per_chunk;

        if (ci_free_count < count || bitmap_paddr == 0 ||
            !apfs_spaceman_paddr_valid(amp, (uint64_t)bitmap_paddr)) {
            brelse(cibp, 0);
            cibp = NULL;
            continue;
        }

        error = apfs_bread(amp, bitmap_paddr, &bp);
        if (error != 0) {
            brelse(cibp, 0);
            cibp = NULL;
            continue;
        }

        const uint8_t *bitmap = (const uint8_t *)bp->b_data;
        uint32_t bit_start = (c_offset == 0) ? start_bit : 0;
        if (bit_start >= expected_blocks)
            bit_start = 0;

        /* Scan from bit_start to end of chunk */
        for (uint32_t bit = bit_start; bit + count <= expected_blocks; bit++) {
            bool run_ok = true;
            for (uint64_t k = 0; k < count; k++) {
                uint32_t b = bit + (uint32_t)k;
                uint64_t blk = chunk_start + b;

                /* Clear bit (0 = free) */
                if ((bitmap[b >> 3] & (1U << (b & 7))) != 0) {
                    run_ok = false;
                    bit = b;
                    break;
                }
                if (!apfs_spaceman_candidate_safe(amp, &excl_table, blk)) {
                    run_ok = false;
                    break;
                }
                if (apfs_resv_is_reserved_locked(amp, blk, 1)) {
                    run_ok = false;
                    break;
                }
            }

            if (run_ok) {
                found_paddr = chunk_start + bit;
                amp->am_resv_pool.rp_last_chunk = chunk_idx;
                amp->am_resv_pool.rp_last_bit = bit + (uint32_t)count;
                found = true;
                break;
            }
        }

        /* If not found on start_chunk, check [0, bit_start) */
        if (!found && c_offset == 0 && bit_start > 0) {
            for (uint32_t bit = 0; bit + count <= bit_start && bit + count <= expected_blocks; bit++) {
                bool run_ok = true;
                for (uint64_t k = 0; k < count; k++) {
                    uint32_t b = bit + (uint32_t)k;
                    uint64_t blk = chunk_start + b;

                    if ((bitmap[b >> 3] & (1U << (b & 7))) != 0) {
                        run_ok = false;
                        bit = b;
                        break;
                    }
                    if (!apfs_spaceman_candidate_safe(amp, &excl_table, blk)) {
                        run_ok = false;
                        break;
                    }
                    if (apfs_resv_is_reserved_locked(amp, blk, 1)) {
                        run_ok = false;
                        break;
                    }
                }

                if (run_ok) {
                    found_paddr = chunk_start + bit;
                    amp->am_resv_pool.rp_last_chunk = chunk_idx;
                    amp->am_resv_pool.rp_last_bit = bit + (uint32_t)count;
                    found = true;
                    break;
                }
            }
        }

        brelse(bp, 0);
        bp = NULL;
        brelse(cibp, 0);
        cibp = NULL;
    }

    brelse(smbp, 0);
    smbp = NULL;

    if (!found) {
        mutex_exit(&amp->am_resv_pool.rp_lock);
        return ENOSPC;
    }

    /* Allocate global reservation entry */
    apfs_resv_entry_t *pool_entry = kmem_zalloc(sizeof(*pool_entry), KM_SLEEP);
    pool_entry->re_paddr = found_paddr;
    pool_entry->re_block_count = count;
    pool_entry->re_tx_id = (tx != NULL) ? tx->rt_tx_id : 0;
    LIST_INSERT_HEAD(&amp->am_resv_pool.rp_entries, pool_entry, re_link);
    amp->am_resv_pool.rp_total_reserved += count;

    /* If a transaction context was provided, track it in the tx handle */
    if (tx != NULL) {
        apfs_resv_entry_t *tx_entry = kmem_zalloc(sizeof(*tx_entry), KM_SLEEP);
        tx_entry->re_paddr = found_paddr;
        tx_entry->re_block_count = count;
        tx_entry->re_tx_id = tx->rt_tx_id;
        LIST_INSERT_HEAD(&tx->rt_entries, tx_entry, re_link);
        tx->rt_count += count;
    }

    mutex_exit(&amp->am_resv_pool.rp_lock);

    *paddrp = (apfs_paddr_t)found_paddr;
    return 0;
}

void
apfs_resv_abort(struct apfsmount *amp, apfs_resv_tx_t *tx)
{
    apfs_resv_entry_t *tx_entry, *tx_tmp;

    if (tx == NULL)
        return;

    mutex_enter(&amp->am_resv_pool.rp_lock);
    tx_entry = LIST_FIRST(&tx->rt_entries);
    while (tx_entry != NULL) {
        tx_tmp = LIST_NEXT(tx_entry, re_link);

        /* Find and remove matching reservation from global pool */
        apfs_resv_entry_t *p_entry, *p_tmp;
        p_entry = LIST_FIRST(&amp->am_resv_pool.rp_entries);
        while (p_entry != NULL) {
            p_tmp = LIST_NEXT(p_entry, re_link);
            if (p_entry->re_paddr == tx_entry->re_paddr &&
                p_entry->re_block_count == tx_entry->re_block_count) {
                LIST_REMOVE(p_entry, re_link);
                if (amp->am_resv_pool.rp_total_reserved >= p_entry->re_block_count)
                    amp->am_resv_pool.rp_total_reserved -= p_entry->re_block_count;
                else
                    amp->am_resv_pool.rp_total_reserved = 0;
                kmem_free(p_entry, sizeof(*p_entry));
                break;
            }
            p_entry = p_tmp;
        }

        LIST_REMOVE(tx_entry, re_link);
        kmem_free(tx_entry, sizeof(*tx_entry));
        tx_entry = tx_tmp;
    }
    tx->rt_count = 0;
    mutex_exit(&amp->am_resv_pool.rp_lock);
}

void
apfs_resv_free(struct apfsmount *amp, apfs_paddr_t paddr, uint64_t count)
{
    apfs_resv_entry_t *entry, *tmp;

    if (count == 0 || paddr < 0)
        return;

    mutex_enter(&amp->am_resv_pool.rp_lock);
    entry = LIST_FIRST(&amp->am_resv_pool.rp_entries);
    while (entry != NULL) {
        tmp = LIST_NEXT(entry, re_link);
        if (entry->re_paddr == (uint64_t)paddr &&
            entry->re_block_count == count) {
            LIST_REMOVE(entry, re_link);
            if (amp->am_resv_pool.rp_total_reserved >= count)
                amp->am_resv_pool.rp_total_reserved -= count;
            else
                amp->am_resv_pool.rp_total_reserved = 0;
            kmem_free(entry, sizeof(*entry));
            break;
        } else if (entry->re_paddr == (uint64_t)paddr && entry->re_block_count > count) {
            entry->re_paddr += count;
            entry->re_block_count -= count;
            if (amp->am_resv_pool.rp_total_reserved >= count)
                amp->am_resv_pool.rp_total_reserved -= count;
            else
                amp->am_resv_pool.rp_total_reserved = 0;
            break;
        }
        entry = tmp;
    }
    mutex_exit(&amp->am_resv_pool.rp_lock);
}

int
apfs_alloc_block(struct apfsmount *amp, apfs_paddr_t *paddrp)
{
    return apfs_resv_alloc(amp, NULL, 1, paddrp);
}

int
apfs_free_block(struct apfsmount *amp, apfs_paddr_t paddr)
{
    apfs_resv_free(amp, paddr, 1);
    return 0;
}

int
apfs_tx_begin(struct apfsmount *amp, apfs_tx_t *tx)
{
    if (amp == NULL || tx == NULL)
        return EINVAL;

    memset(tx, 0, sizeof(*tx));
    tx->tx_amp = amp;
    tx->tx_xid = amp->am_checkpoint_xid + 1;
    tx->tx_state = APFS_TX_STATE_ACTIVE;
    tx->tx_resv.rt_tx_id = tx->tx_xid;
    tx->tx_resv.rt_count = 0;
    LIST_INIT(&tx->tx_resv.rt_entries);
    tx->tx_map_count = 0;

    return 0;
}

int
apfs_tx_alloc_block(apfs_tx_t *tx, uint64_t count, apfs_paddr_t *paddrp)
{
    if (tx == NULL || tx->tx_amp == NULL || tx->tx_state != APFS_TX_STATE_ACTIVE)
        return EINVAL;

    return apfs_resv_alloc(tx->tx_amp, &tx->tx_resv, count, paddrp);
}

int
apfs_tx_add_mapping(apfs_tx_t *tx, uint32_t type, uint32_t subtype,
    uint32_t size, oid_t fs_oid, oid_t oid, apfs_paddr_t paddr)
{
    checkpoint_mapping_t *entry;

    if (tx == NULL || tx->tx_state != APFS_TX_STATE_ACTIVE)
        return EINVAL;

    if (tx->tx_map_count >= APFS_TX_MAX_MAPPINGS)
        return ENOSPC;

    entry = &tx->tx_mappings[tx->tx_map_count++];
    entry->cpm_type = htole32(type);
    entry->cpm_subtype = htole32(subtype);
    entry->cpm_size = htole32(size);
    entry->cpm_pad = 0;
    entry->cpm_fs_oid = htole64(fs_oid);
    entry->cpm_oid = htole64(oid);
    entry->cpm_paddr = (apfs_paddr_t)htole64((uint64_t)paddr);

    return 0;
}

void
apfs_tx_abort(apfs_tx_t *tx)
{
    if (tx == NULL || tx->tx_state == APFS_TX_STATE_INACTIVE)
        return;

    if (tx->tx_amp != NULL)
        apfs_resv_abort(tx->tx_amp, &tx->tx_resv);

    tx->tx_map_count = 0;
    tx->tx_state = APFS_TX_STATE_ABORTED;
}

#define APFS_TX_UPDATE_MAX_CHUNKS 64
#define APFS_TX_UPDATE_MAX_CIBS   16

int
apfs_spaceman_tx_update(apfs_tx_t *tx)
{
    struct apfsmount *amp;
    struct buf *smbp = NULL, *cibbp = NULL, *bmbp = NULL, *bp = NULL;
    spaceman_phys_t *sm, *new_sm = NULL;
    apfs_paddr_t sm_paddr, new_sm_paddr;
    uint32_t blocks_per_chunk, chunks_per_cib, cib_count, addr_offset;
    int error = 0;

    if (tx == NULL || tx->tx_amp == NULL ||
        (tx->tx_state != APFS_TX_STATE_ACTIVE && tx->tx_state != APFS_TX_STATE_COMMITTING))
        return EINVAL;

    amp = tx->tx_amp;
    if (LIST_EMPTY(&tx->tx_resv.rt_entries))
        return 0;

    if (le64toh(amp->am_nx.nx_spaceman_oid) == 0)
        return EINVAL;

    error = apfs_checkpoint_lookup(amp, le64toh(amp->am_nx.nx_spaceman_oid), 0, &sm_paddr);
    if (error != 0)
        return error;

    error = apfs_bread(amp, sm_paddr, &smbp);
    if (error != 0)
        return error;

    sm = (spaceman_phys_t *)smbp->b_data;
    blocks_per_chunk = le32toh(sm->sm_blocks_per_chunk);
    chunks_per_cib = le32toh(sm->sm_chunks_per_cib);
    cib_count = le32toh(sm->sm_dev[0].sm_cib_count);
    addr_offset = le32toh(sm->sm_dev[0].sm_addr_offset);

    if (blocks_per_chunk == 0 || chunks_per_cib == 0 || cib_count == 0) {
        brelse(smbp, 0);
        return EINVAL;
    }

    struct chunk_mod {
        uint64_t     cm_chunk_idx;
        uint32_t     cm_cib_idx;
        uint32_t     cm_chunk_in_cib;
        apfs_paddr_t cm_old_bm;
        apfs_paddr_t cm_new_bm;
        uint32_t     cm_alloc_count;
        uint8_t     *cm_bitmap;
    } chunks[APFS_TX_UPDATE_MAX_CHUNKS];
    uint32_t num_chunks = 0;

    struct cib_mod {
        uint32_t                 cibm_idx;
        apfs_paddr_t             cibm_old_paddr;
        apfs_paddr_t             cibm_new_paddr;
        chunk_info_block_phys_t *cibm_data;
    } cibs[APFS_TX_UPDATE_MAX_CIBS];
    uint32_t num_cibs = 0;

    memset(chunks, 0, sizeof(chunks));
    memset(cibs, 0, sizeof(cibs));

    bool new_allocs = true;

    while (new_allocs) {
        new_allocs = false;
        apfs_resv_entry_t *re;

        LIST_FOREACH(re, &tx->tx_resv.rt_entries, re_link) {
            for (uint64_t b = 0; b < re->re_block_count; b++) {
                uint64_t p = re->re_paddr + b;
                uint64_t chk = p / blocks_per_chunk;
                uint32_t cib_idx = chk / chunks_per_cib;
                uint32_t chunk_in_cib = chk % chunks_per_cib;
                uint32_t bit = p % blocks_per_chunk;

                int c_idx = -1;
                for (uint32_t i = 0; i < num_chunks; i++) {
                    if (chunks[i].cm_chunk_idx == chk) {
                        c_idx = i;
                        break;
                    }
                }

                if (c_idx == -1) {
                    if (num_chunks >= APFS_TX_UPDATE_MAX_CHUNKS) {
                        error = ENOSPC;
                        goto out;
                    }
                    c_idx = num_chunks++;
                    chunks[c_idx].cm_chunk_idx = chk;
                    chunks[c_idx].cm_cib_idx = cib_idx;
                    chunks[c_idx].cm_chunk_in_cib = chunk_in_cib;
                    chunks[c_idx].cm_bitmap = (uint8_t *)calloc(1, amp->am_block_size);

                    const uint64_t *cib_paddrs = (const uint64_t *)((const char *)sm + addr_offset);
                    apfs_paddr_t old_cib_paddr = (apfs_paddr_t)le64toh(cib_paddrs[cib_idx]);

                    error = apfs_bread(amp, old_cib_paddr, &cibbp);
                    if (error != 0)
                        goto out;

                    chunk_info_block_phys_t *cib = (chunk_info_block_phys_t *)cibbp->b_data;
                    chunks[c_idx].cm_old_bm = (apfs_paddr_t)le64toh((uint64_t)cib->cib_chunk_info[chunk_in_cib].ci_bitmap_addr);

                    if (chunks[c_idx].cm_old_bm != 0) {
                        error = apfs_bread(amp, chunks[c_idx].cm_old_bm, &bmbp);
                        if (error != 0) {
                            brelse(cibbp, 0);
                            goto out;
                        }
                        memcpy(chunks[c_idx].cm_bitmap, bmbp->b_data, amp->am_block_size);
                        brelse(bmbp, 0);
                    }

                    int cb_idx = -1;
                    for (uint32_t j = 0; j < num_cibs; j++) {
                        if (cibs[j].cibm_idx == cib_idx) {
                            cb_idx = j;
                            break;
                        }
                    }
                    if (cb_idx == -1) {
                        if (num_cibs >= APFS_TX_UPDATE_MAX_CIBS) {
                            brelse(cibbp, 0);
                            error = ENOSPC;
                            goto out;
                        }
                        cb_idx = num_cibs++;
                        cibs[cb_idx].cibm_idx = cib_idx;
                        cibs[cb_idx].cibm_old_paddr = old_cib_paddr;
                        cibs[cb_idx].cibm_data = (chunk_info_block_phys_t *)malloc(amp->am_block_size);
                        memcpy(cibs[cb_idx].cibm_data, cibbp->b_data, amp->am_block_size);

                        error = apfs_tx_alloc_block(tx, 1, &cibs[cb_idx].cibm_new_paddr);
                        if (error != 0) {
                            brelse(cibbp, 0);
                            goto out;
                        }
                        new_allocs = true;
                    }
                    brelse(cibbp, 0);

                    error = apfs_tx_alloc_block(tx, 1, &chunks[c_idx].cm_new_bm);
                    if (error != 0)
                        goto out;
                    new_allocs = true;
                }

                if ((chunks[c_idx].cm_bitmap[bit >> 3] & (1U << (bit & 7))) == 0) {
                    chunks[c_idx].cm_bitmap[bit >> 3] |= (1U << (bit & 7));
                    chunks[c_idx].cm_alloc_count++;
                }
            }
        }
    }

    error = apfs_tx_alloc_block(tx, 1, &new_sm_paddr);
    if (error != 0)
        goto out;

    {
        uint64_t p = new_sm_paddr;
        uint64_t chk = p / blocks_per_chunk;
        uint32_t bit = p % blocks_per_chunk;
        for (uint32_t i = 0; i < num_chunks; i++) {
            if (chunks[i].cm_chunk_idx == chk) {
                if ((chunks[i].cm_bitmap[bit >> 3] & (1U << (bit & 7))) == 0) {
                    chunks[i].cm_bitmap[bit >> 3] |= (1U << (bit & 7));
                    chunks[i].cm_alloc_count++;
                }
                break;
            }
        }
    }

    /* 1. Write all modified bitmap blocks */
    for (uint32_t i = 0; i < num_chunks; i++) {
        error = apfs_getblk(amp, chunks[i].cm_new_bm, &bp);
        if (error != 0)
            goto out;
        memcpy(bp->b_data, chunks[i].cm_bitmap, amp->am_block_size);
        error = apfs_bwrite(amp, chunks[i].cm_new_bm, bp);
        if (error != 0)
            goto out;
    }

    /* 2. Write all modified CIB blocks */
    for (uint32_t j = 0; j < num_cibs; j++) {
        chunk_info_block_phys_t *cib = cibs[j].cibm_data;
        apfs_obj_init(&cib->cib_o, (oid_t)cibs[j].cibm_new_paddr, tx->tx_xid,
            OBJ_SPACEMAN_CIB | OBJ_PHYSICAL, 0);

        for (uint32_t i = 0; i < num_chunks; i++) {
            if (chunks[i].cm_cib_idx == cibs[j].cibm_idx) {
                chunk_info_phys_t *ci = &cib->cib_chunk_info[chunks[i].cm_chunk_in_cib];
                uint32_t old_free = le32toh(ci->ci_free_count);
                ci->ci_xid = htole64(tx->tx_xid);
                ci->ci_free_count = htole32(old_free >= chunks[i].cm_alloc_count ?
                    old_free - chunks[i].cm_alloc_count : 0);
                ci->ci_bitmap_addr = (apfs_paddr_t)htole64((uint64_t)chunks[i].cm_new_bm);
            }
        }
        apfs_obj_set_cksum(amp, cib);

        error = apfs_getblk(amp, cibs[j].cibm_new_paddr, &bp);
        if (error != 0)
            goto out;
        memcpy(bp->b_data, cib, amp->am_block_size);
        error = apfs_bwrite(amp, cibs[j].cibm_new_paddr, bp);
        if (error != 0)
            goto out;
    }

    /* 3. Write Space Manager block */
    new_sm = (spaceman_phys_t *)malloc(amp->am_block_size);
    memcpy(new_sm, sm, amp->am_block_size);
    apfs_obj_init(&new_sm->o, le64toh(amp->am_nx.nx_spaceman_oid), tx->tx_xid,
        OBJ_SPACEMAN | OBJ_EPHEMERAL, 0);

    uint64_t old_sm_free = le64toh(new_sm->sm_dev[0].sm_free_count);
    uint64_t total_allocated = tx->tx_resv.rt_count;
    new_sm->sm_dev[0].sm_free_count = htole64(old_sm_free >= total_allocated ?
        old_sm_free - total_allocated : 0);

    uint64_t *sm_cib_paddrs = (uint64_t *)((char *)new_sm + addr_offset);
    for (uint32_t j = 0; j < num_cibs; j++) {
        sm_cib_paddrs[cibs[j].cibm_idx] = htole64((uint64_t)cibs[j].cibm_new_paddr);
    }

    apfs_obj_set_cksum(amp, new_sm);

    error = apfs_getblk(amp, new_sm_paddr, &bp);
    if (error != 0)
        goto out;
    memcpy(bp->b_data, new_sm, amp->am_block_size);
    error = apfs_bwrite(amp, new_sm_paddr, bp);
    if (error != 0)
        goto out;

    /* 4. Register Space Manager mapping in transaction */
    error = apfs_tx_add_mapping(tx, OBJ_SPACEMAN | OBJ_EPHEMERAL, 0, amp->am_block_size, 0,
        le64toh(amp->am_nx.nx_spaceman_oid), new_sm_paddr);

out:
    if (smbp != NULL)
        brelse(smbp, 0);
    if (new_sm != NULL)
        free(new_sm);
    for (uint32_t i = 0; i < num_chunks; i++) {
        if (chunks[i].cm_bitmap != NULL)
            free(chunks[i].cm_bitmap);
    }
    for (uint32_t j = 0; j < num_cibs; j++) {
        if (cibs[j].cibm_data != NULL)
            free(cibs[j].cibm_data);
    }

    return error;
}

int
apfs_tx_commit(apfs_tx_t *tx)
{
    struct apfsmount *amp;
    struct buf *bp = NULL;
    uint64_t desc_base;
    uint32_t desc_blocks, old_desc_index, old_desc_len;
    uint32_t new_desc_index, new_desc_len, num_map_blocks;
    uint32_t capacity, map_count;
    int error;

    if (tx == NULL || tx->tx_amp == NULL || tx->tx_state != APFS_TX_STATE_ACTIVE)
        return EINVAL;

    amp = tx->tx_amp;
    desc_blocks = amp->am_desc_blocks;
    desc_base = le64toh(amp->am_nx.nx_xp_desc_base);
    old_desc_index = le32toh(amp->am_nx.nx_xp_desc_index);
    old_desc_len = le32toh(amp->am_nx.nx_xp_desc_len);

    if (desc_blocks == 0 || desc_base == 0)
        return EINVAL;

    /* Phase 1: Update Space Manager, CIBs, and Bitmaps if any allocations made */
    error = apfs_spaceman_tx_update(tx);
    if (error != 0) {
        apfs_tx_abort(tx);
        return error;
    }

    capacity = (amp->am_block_size - sizeof(checkpoint_map_phys_t)) /
        sizeof(checkpoint_mapping_t);
    if (capacity == 0)
        return EINVAL;

    map_count = tx->tx_map_count;
    num_map_blocks = (map_count == 0) ? 1 : (map_count + capacity - 1) / capacity;
    new_desc_len = num_map_blocks + 1;

    if (new_desc_len > desc_blocks)
        return ENOSPC;

    new_desc_index = (old_desc_index + old_desc_len) % desc_blocks;
    tx->tx_state = APFS_TX_STATE_COMMITTING;

    /* Phase 2a: Write Checkpoint Map blocks to descriptor ring */
    for (uint32_t i = 0; i < num_map_blocks; i++) {
        uint32_t slot = (new_desc_index + i) % desc_blocks;
        apfs_paddr_t map_paddr = (apfs_paddr_t)(desc_base + slot);
        checkpoint_map_phys_t *map;
        uint32_t start_idx, entries_in_block, flags = 0;

        error = apfs_getblk(amp, map_paddr, &bp);
        if (error != 0) {
            apfs_tx_abort(tx);
            return error;
        }

        map = (checkpoint_map_phys_t *)bp->b_data;
        memset(map, 0, amp->am_block_size);
        apfs_obj_init(&map->cpm_o, (oid_t)map_paddr, tx->tx_xid,
            OBJ_CHECKPOINT_MAP | OBJ_PHYSICAL, 0);

        if (i == num_map_blocks - 1)
            flags |= CHECKPOINT_MAP_LAST;
        map->cpm_flags = htole32(flags);

        start_idx = i * capacity;
        entries_in_block = (start_idx + capacity <= map_count) ?
            capacity : (map_count > start_idx ? map_count - start_idx : 0);
        map->cpm_count = htole32(entries_in_block);

        for (uint32_t j = 0; j < entries_in_block; j++) {
            map->cpm_map[j] = tx->tx_mappings[start_idx + j];
        }

        apfs_obj_set_cksum(amp, map);

        error = apfs_bwrite(amp, map_paddr, bp);
        if (error != 0) {
            apfs_tx_abort(tx);
            return error;
        }
    }

    /* Phase 2b: Write updated Container Superblock to descriptor ring */
    uint32_t sb_slot = (new_desc_index + num_map_blocks) % desc_blocks;
    apfs_paddr_t sb_paddr = (apfs_paddr_t)(desc_base + sb_slot);
    nx_superblock_t *new_nx;

    error = apfs_getblk(amp, sb_paddr, &bp);
    if (error != 0) {
        apfs_tx_abort(tx);
        return error;
    }

    new_nx = (nx_superblock_t *)bp->b_data;
    memcpy(new_nx, &amp->am_nx, sizeof(*new_nx));
    apfs_obj_init(&new_nx->nx_o, 1, tx->tx_xid,
        OBJ_CONTAINER_SUPERBLOCK | OBJ_PHYSICAL, 0);
    new_nx->nx_next_xid = htole64(tx->tx_xid + 1);
    new_nx->nx_xp_desc_index = htole32(new_desc_index);
    new_nx->nx_xp_desc_len = htole32(new_desc_len);
    apfs_obj_set_cksum(amp, new_nx);

    error = apfs_bwrite(amp, sb_paddr, bp);
    if (error != 0) {
        apfs_tx_abort(tx);
        return error;
    }

    /* Update in-memory mount state */
    amp->am_checkpoint_xid = tx->tx_xid;
    memcpy(&amp->am_nx, new_nx, sizeof(amp->am_nx));

    /* Clean up transaction handle and release from global reservation pool */
    mutex_enter(&amp->am_resv_pool.rp_lock);
    apfs_resv_entry_t *re, *tmp;
    re = LIST_FIRST(&tx->tx_resv.rt_entries);
    while (re != NULL) {
        tmp = LIST_NEXT(re, re_link);
        apfs_resv_entry_t *pe, *ptmp;
        pe = LIST_FIRST(&amp->am_resv_pool.rp_entries);
        while (pe != NULL) {
            ptmp = LIST_NEXT(pe, re_link);
            if (pe->re_paddr == re->re_paddr && pe->re_block_count == re->re_block_count) {
                LIST_REMOVE(pe, re_link);
                if (amp->am_resv_pool.rp_total_reserved >= pe->re_block_count)
                    amp->am_resv_pool.rp_total_reserved -= pe->re_block_count;
                else
                    amp->am_resv_pool.rp_total_reserved = 0;
                free(pe);
                break;
            }
            pe = ptmp;
        }
        LIST_REMOVE(re, re_link);
        free(re);
        re = tmp;
    }
    tx->tx_resv.rt_count = 0;
    mutex_exit(&amp->am_resv_pool.rp_lock);
    tx->tx_state = APFS_TX_STATE_COMMITTED;

    return 0;
}

static uint32_t
apfs_name_hash(const char *name, size_t len)
{
    uint32_t hash = 0;
    for (size_t i = 0; i < len; i++) {
        hash = (hash * 33) + (uint8_t)name[i];
    }
    return hash;
}

static int
apfs_btree_cmp(const void *k1, const void *k2, uint32_t subtype)
{
    const j_key_t *jk1 = k1;
    const j_key_t *jk2 = k2;
    uint64_t id1 = le64toh(jk1->obj_id_and_type) & OBJ_ID_MASK;
    uint64_t id2 = le64toh(jk2->obj_id_and_type) & OBJ_ID_MASK;
    uint64_t type1 = (le64toh(jk1->obj_id_and_type) & OBJ_TYPE_MASK) >> OBJ_TYPE_SHIFT;
    uint64_t type2 = (le64toh(jk2->obj_id_and_type) & OBJ_TYPE_MASK) >> OBJ_TYPE_SHIFT;

    if (id1 < id2) return -1;
    if (id1 > id2) return 1;
    if (type1 < type2) return -1;
    if (type1 > type2) return 1;

    if (subtype == APFS_TYPE_EXTENT) {
        const j_extent_key_t *ek1 = k1;
        const j_extent_key_t *ek2 = k2;
        uint64_t addr1 = le64toh(ek1->logical_addr);
        uint64_t addr2 = le64toh(ek2->logical_addr);
        if (addr1 < addr2) return -1;
        if (addr1 > addr2) return 1;
    }
    return 0;
}

static int
apfs_btree_entry(struct apfsmount *amp, btree_node_phys_t *node,
    const btree_info_t *info, uint32_t index, const void **keyp,
    size_t *key_lenp, const void **valp, size_t *val_lenp)
{
    uint8_t *data = (uint8_t *)node + sizeof(*node);
    uint32_t flags = le16toh(node->btn_flags);
    uint32_t nkeys = le32toh(node->btn_nkeys);
    uint32_t table_off = le16toh(node->btn_table_space_off);
    uint32_t table_len = le16toh(node->btn_table_space_len);
    uint32_t data_end = amp->am_block_size;
    uint32_t toc_size, key_off, key_len, val_off, val_len;
    uint32_t key_area, val_start;

    if ((flags & BTNODE_ROOT) != 0)
        data_end -= sizeof(*info);
    if (index >= nkeys || table_off > amp->am_block_size - sizeof(*node) ||
        table_len > amp->am_block_size - sizeof(*node) - table_off)
        return EINVAL;

    if (flags & BTNODE_FIXED_KV_SIZE) {
        const btree_toc_fixed_entry_t *toc;
        toc_size = sizeof(*toc);
        if (info->bt_key_size == 0 ||
            ((flags & BTNODE_LEAF) && info->bt_val_size == 0))
            return EINVAL;
        if ((uint64_t)nkeys * toc_size > table_len)
            return EINVAL;
        toc = (const btree_toc_fixed_entry_t *)(data + table_off);
        key_off = le16toh(toc[index].key_off);
        val_off = le16toh(toc[index].val_off);
        key_len = le32toh(info->bt_key_size);
        val_len = (flags & BTNODE_LEAF) ?
            le32toh(info->bt_val_size) : sizeof(oid_t);
    } else {
        const btree_toc_entry_t *toc;
        toc_size = sizeof(*toc);
        if ((uint64_t)nkeys * toc_size > table_len)
            return EINVAL;
        toc = (const btree_toc_entry_t *)(data + table_off);
        key_off = le16toh(toc[index].key_off);
        key_len = le16toh(toc[index].key_len);
        val_off = le16toh(toc[index].val_off);
        val_len = le16toh(toc[index].val_len);
    }

    key_area = sizeof(*node) + table_off + table_len;
    if (key_area > data_end || key_off > data_end - key_area ||
        key_len > data_end - key_area - key_off ||
        val_off > data_end || val_len > val_off)
        return EINVAL;
    val_start = data_end - val_off;
    if (val_start < key_area + key_off + key_len)
        return EINVAL;

    *keyp = (uint8_t *)node + key_area + key_off;
    *key_lenp = key_len;
    *valp = (uint8_t *)node + val_start;
    *val_lenp = val_len;
    return 0;
}

static int
apfs_btree_resolve_child(struct apfsmount *amp, oid_t omap_oid,
    uint32_t tree_flags, oid_t child_oid, apfs_paddr_t *paddrp)
{
    if (tree_flags & BTREE_PHYSICAL) {
        if (child_oid > INT64_MAX)
            return EINVAL;
        *paddrp = (apfs_paddr_t)child_oid;
        return 0;
    }
    if (tree_flags & BTREE_EPHEMERAL) {
        return apfs_checkpoint_lookup(amp, child_oid, 0, paddrp);
    }
    *paddrp = (apfs_paddr_t)child_oid;
    return 0;
}

int
apfs_btree_insert_record(apfs_tx_t *tx, oid_t omap_oid, oid_t *tree_oid,
    const void *key, size_t key_len, const void *val, size_t val_len)
{
    struct apfsmount *amp;
    apfs_paddr_t root_paddr, curr_paddr;
    apfs_btree_path_t path;
    struct buf *bp;
    btree_info_t info;
    uint32_t tree_flags = 0;
    int error;

    if (tx == NULL || tx->tx_amp == NULL || tree_oid == NULL ||
        key == NULL || val == NULL)
        return EINVAL;

    amp = tx->tx_amp;
    root_paddr = (apfs_paddr_t)*tree_oid;

    memset(&path, 0, sizeof(path));
    curr_paddr = root_paddr;

    /* 1. Navigate from root to leaf, recording path */
    while (curr_paddr != 0 && path.bp_depth < APFS_BTREE_MAX_DEPTH) {
        error = apfs_bread(amp, curr_paddr, &bp);
        if (error != 0)
            return error;

        btree_node_phys_t *node = (btree_node_phys_t *)bp->b_data;
        uint16_t flags = le16toh(node->btn_flags);
        uint16_t level = le16toh(node->btn_level);
        uint32_t nkeys = le32toh(node->btn_nkeys);

        if (path.bp_depth == 0) {
            if ((flags & BTNODE_ROOT) == 0) {
                brelse(bp, 0);
                return EINVAL;
            }
            memcpy(&info, (char *)node + amp->am_block_size - sizeof(info), sizeof(info));
            tree_flags = le32toh(info.bt_flags);
        }

        path.bp_entries[path.bp_depth].pe_paddr = curr_paddr;
        path.bp_entries[path.bp_depth].pe_flags = flags;

        if (level == 0 || (flags & BTNODE_LEAF) != 0) {
            uint32_t ins_idx = nkeys;
            for (uint32_t i = 0; i < nkeys; i++) {
                const void *k_ptr, *v_ptr;
                size_t k_len, v_len;
                error = apfs_btree_entry(amp, node, &info, i, &k_ptr, &k_len, &v_ptr, &v_len);
                if (error != 0) {
                    brelse(bp, 0);
                    return error;
                }
                uint32_t subtype = (flags & BTNODE_FIXED_KV_SIZE) ? 0 : APFS_TYPE_ANY;
                if (apfs_btree_cmp(key, k_ptr, subtype) <= 0) {
                    ins_idx = i;
                    break;
                }
            }
            path.bp_entries[path.bp_depth].pe_idx = ins_idx;
            path.bp_depth++;
            brelse(bp, 0);
            break;
        }

        uint32_t child_idx = 0;
        for (uint32_t i = 0; i < nkeys; i++) {
            const void *k_ptr, *v_ptr;
            size_t k_len, v_len;
            error = apfs_btree_entry(amp, node, &info, i, &k_ptr, &k_len, &v_ptr, &v_len);
            if (error != 0) {
                brelse(bp, 0);
                return error;
            }
            if (apfs_btree_cmp(key, k_ptr, APFS_TYPE_ANY) >= 0)
                child_idx = i;
            else
                break;
        }

        path.bp_entries[path.bp_depth].pe_idx = child_idx;
        const void *k_ptr, *v_ptr;
        size_t k_len, v_len;
        error = apfs_btree_entry(amp, node, &info, child_idx, &k_ptr, &k_len, &v_ptr, &v_len);
        if (error != 0) {
            brelse(bp, 0);
            return error;
        }

        oid_t child_oid = le64toh(*(const oid_t *)v_ptr);
        brelse(bp, 0);

        error = apfs_btree_resolve_child(amp, omap_oid, tree_flags, child_oid, &curr_paddr);
        if (error != 0)
            return error;

        path.bp_depth++;
    }

    if (path.bp_depth == 0)
        return EINVAL;

    /* 2. Insert into leaf node with Copy-on-Write */
    uint32_t leaf_depth = path.bp_depth - 1;
    apfs_paddr_t old_leaf_paddr = path.bp_entries[leaf_depth].pe_paddr;
    uint32_t ins_idx = path.bp_entries[leaf_depth].pe_idx;

    error = apfs_bread(amp, old_leaf_paddr, &bp);
    if (error != 0)
        return error;

    btree_node_phys_t *old_leaf = (btree_node_phys_t *)bp->b_data;
    uint16_t leaf_flags = le16toh(old_leaf->btn_flags);
    uint32_t old_nkeys = le32toh(old_leaf->btn_nkeys);
    uint32_t table_off = le16toh(old_leaf->btn_table_space_off);
    uint32_t table_len = le16toh(old_leaf->btn_table_space_len);
    uint32_t data_end = amp->am_block_size - ((leaf_flags & BTNODE_ROOT) ? sizeof(btree_info_t) : 0);
    uint32_t toc_size = (leaf_flags & BTNODE_FIXED_KV_SIZE) ?
        sizeof(btree_toc_fixed_entry_t) : sizeof(btree_toc_entry_t);

    apfs_paddr_t new_leaf_paddr;
    error = apfs_tx_alloc_block(tx, 1, &new_leaf_paddr);
    if (error != 0) {
        brelse(bp, 0);
        return error;
    }

    struct buf *new_bp;
    error = apfs_getblk(amp, new_leaf_paddr, &new_bp);
    if (error != 0) {
        brelse(bp, 0);
        return error;
    }

    btree_node_phys_t *new_leaf = (btree_node_phys_t *)new_bp->b_data;
    memset(new_leaf, 0, amp->am_block_size);
    memcpy(new_leaf, old_leaf, sizeof(*old_leaf));

    uint8_t *new_data = (uint8_t *)new_leaf + sizeof(*new_leaf);
    uint32_t key_area_start = sizeof(*new_leaf) + table_off + table_len + toc_size;
    uint32_t curr_key_off = 0;
    uint32_t curr_val_off = 0;

    uint32_t new_nkeys = old_nkeys + 1;
    new_leaf->btn_nkeys = htole32(new_nkeys);
    new_leaf->btn_table_space_len = htole16(table_len + toc_size);

    for (uint32_t i = 0; i < new_nkeys; i++) {
        const void *k_data, *v_data;
        size_t k_sz, v_sz;

        if (i == ins_idx) {
            k_data = key;
            k_sz = key_len;
            v_data = val;
            v_sz = val_len;
        } else {
            uint32_t src_i = (i < ins_idx) ? i : i - 1;
            error = apfs_btree_entry(amp, old_leaf, &info, src_i,
                &k_data, &k_sz, &v_data, &v_sz);
            if (error != 0) {
                brelse(bp, 0);
                brelse(new_bp, 0);
                return error;
            }
        }

        memcpy((uint8_t *)new_leaf + key_area_start + curr_key_off, k_data, k_sz);
        curr_val_off += v_sz;
        memcpy((uint8_t *)new_leaf + data_end - curr_val_off, v_data, v_sz);

        if (leaf_flags & BTNODE_FIXED_KV_SIZE) {
            btree_toc_fixed_entry_t *toc = (btree_toc_fixed_entry_t *)(new_data + table_off);
            toc[i].key_off = htole16(curr_key_off);
            toc[i].val_off = htole16(curr_val_off);
        } else {
            btree_toc_entry_t *toc = (btree_toc_entry_t *)(new_data + table_off);
            toc[i].key_off = htole16(curr_key_off);
            toc[i].key_len = htole16(k_sz);
            toc[i].val_off = htole16(curr_val_off);
            toc[i].val_len = htole16(v_sz);
        }

        curr_key_off += k_sz;
    }

    brelse(bp, 0);

    if (leaf_flags & BTNODE_ROOT) {
        btree_info_t *new_info = (btree_info_t *)((char *)new_leaf + amp->am_block_size - sizeof(btree_info_t));
        memcpy(new_info, &info, sizeof(info));
        new_info->bt_key_count = htole32(le32toh(info.bt_key_count) + 1);
    }

    apfs_obj_init(&new_leaf->btn_o, (oid_t)new_leaf_paddr, tx->tx_xid,
        OBJ_BTREE_NODE | OBJ_PHYSICAL, 0);
    apfs_obj_set_cksum(amp, new_leaf);

    error = apfs_bwrite(amp, new_leaf_paddr, new_bp);
    if (error != 0)
        return error;

    /* 3. Propagate up the path stack if internal nodes exist */
    apfs_paddr_t child_paddr = new_leaf_paddr;
    for (int d = (int)leaf_depth - 1; d >= 0; d--) {
        apfs_paddr_t old_parent_paddr = path.bp_entries[d].pe_paddr;
        uint32_t p_child_idx = path.bp_entries[d].pe_idx;

        error = apfs_bread(amp, old_parent_paddr, &bp);
        if (error != 0)
            return error;

        btree_node_phys_t *old_parent = (btree_node_phys_t *)bp->b_data;
        uint16_t p_flags = le16toh(old_parent->btn_flags);

        apfs_paddr_t new_parent_paddr;
        error = apfs_tx_alloc_block(tx, 1, &new_parent_paddr);
        if (error != 0) {
            brelse(bp, 0);
            return error;
        }

        error = apfs_getblk(amp, new_parent_paddr, &new_bp);
        if (error != 0) {
            brelse(bp, 0);
            return error;
        }

        btree_node_phys_t *new_parent = (btree_node_phys_t *)new_bp->b_data;
        memcpy(new_parent, old_parent, amp->am_block_size);
        brelse(bp, 0);

        uint32_t p_data_end = amp->am_block_size - ((p_flags & BTNODE_ROOT) ? sizeof(btree_info_t) : 0);
        uint8_t *p_data = (uint8_t *)new_parent + sizeof(*new_parent);
        uint32_t p_table_off = le16toh(new_parent->btn_table_space_off);

        if (p_flags & BTNODE_FIXED_KV_SIZE) {
            btree_toc_fixed_entry_t *toc = (btree_toc_fixed_entry_t *)(p_data + p_table_off);
            uint32_t v_off = le16toh(toc[p_child_idx].val_off);
            oid_t *val_ptr = (oid_t *)((uint8_t *)new_parent + p_data_end - v_off);
            *val_ptr = htole64((uint64_t)child_paddr);
        } else {
            btree_toc_entry_t *toc = (btree_toc_entry_t *)(p_data + p_table_off);
            uint32_t v_off = le16toh(toc[p_child_idx].val_off);
            oid_t *val_ptr = (oid_t *)((uint8_t *)new_parent + p_data_end - v_off);
            *val_ptr = htole64((uint64_t)child_paddr);
        }

        if (p_flags & BTNODE_ROOT) {
            btree_info_t *p_info = (btree_info_t *)((char *)new_parent + amp->am_block_size - sizeof(btree_info_t));
            p_info->bt_key_count = htole32(le32toh(p_info->bt_key_count) + 1);
        }

        apfs_obj_init(&new_parent->btn_o, (oid_t)new_parent_paddr, tx->tx_xid,
            OBJ_BTREE_NODE | OBJ_PHYSICAL, 0);
        apfs_obj_set_cksum(amp, new_parent);

        error = apfs_bwrite(amp, new_parent_paddr, new_bp);
        if (error != 0)
            return error;

        child_paddr = new_parent_paddr;
    }

    *tree_oid = (oid_t)child_paddr;
    return 0;
}

int
apfs_create_file(struct apfsmount *amp, oid_t parent_oid, const char *name,
    mode_t mode, uid_t uid, gid_t gid, oid_t *new_oidp)
{
    apfs_tx_t tx;
    oid_t new_ino_oid = 0x5000;
    uint32_t name_len = strlen(name);
    uint32_t name_hash = apfs_name_hash(name, name_len);
    int error;

    error = apfs_tx_begin(amp, &tx);
    if (error != 0)
        return error;

    j_key_t ino_key;
    ino_key.obj_id_and_type = htole64((new_ino_oid & OBJ_ID_MASK) |
        ((uint64_t)APFS_TYPE_INODE << OBJ_TYPE_SHIFT));

    j_inode_val_t ino_val;
    memset(&ino_val, 0, sizeof(ino_val));
    ino_val.parent_id = htole64(parent_oid);
    ino_val.private_id = htole64(new_ino_oid);
    ino_val.nchildren_or_nlink = htole32(1);
    ino_val.owner = htole32(uid);
    ino_val.group = htole32(gid);
    ino_val.mode = htole16(mode | S_IFREG);

    oid_t root_tree_oid = 0;
    /* Create a standalone btree node if tree_oid is 0 */
    apfs_paddr_t tree_root_paddr;
    error = apfs_tx_alloc_block(&tx, 1, &tree_root_paddr);
    if (error != 0) {
        apfs_tx_abort(&tx);
        return error;
    }
    struct buf *root_bp;
    error = apfs_getblk(amp, tree_root_paddr, &root_bp);
    if (error != 0) {
        apfs_tx_abort(&tx);
        return error;
    }
    btree_node_phys_t *rnode = (btree_node_phys_t *)root_bp->b_data;
    memset(rnode, 0, amp->am_block_size);
    rnode->btn_flags = htole16(BTNODE_ROOT | BTNODE_LEAF);
    rnode->btn_level = 0;
    rnode->btn_nkeys = 0;
    rnode->btn_table_space_off = 0;
    rnode->btn_table_space_len = 0;

    btree_info_t *rinfo = (btree_info_t *)((char *)rnode + amp->am_block_size - sizeof(btree_info_t));
    rinfo->bt_flags = htole32(BTREE_PHYSICAL);
    rinfo->bt_node_size = htole32(amp->am_block_size);
    apfs_obj_init(&rnode->btn_o, (oid_t)tree_root_paddr, tx.tx_xid,
        OBJ_BTREE_NODE | OBJ_PHYSICAL, 0);
    apfs_obj_set_cksum(amp, rnode);
    error = apfs_bwrite(amp, tree_root_paddr, root_bp);
    if (error != 0) {
        apfs_tx_abort(&tx);
        return error;
    }
    root_tree_oid = tree_root_paddr;

    error = apfs_btree_insert_record(&tx, 0, &root_tree_oid,
        &ino_key, sizeof(ino_key), &ino_val, sizeof(ino_val));
    if (error != 0) {
        apfs_tx_abort(&tx);
        return error;
    }

    size_t drec_key_size = sizeof(j_drec_hashed_key_t) + name_len + 1;
    j_drec_hashed_key_t *drec_key = calloc(1, drec_key_size);
    drec_key->hdr.obj_id_and_type = htole64((parent_oid & OBJ_ID_MASK) |
        ((uint64_t)APFS_TYPE_DIR_REC << OBJ_TYPE_SHIFT));
    drec_key->name_len_and_hash = htole32((name_hash << DREC_HASH_SHIFT) |
        (name_len & DREC_NLEN_MASK));
    memcpy(drec_key->name, name, name_len);

    j_drec_val_t drec_val;
    memset(&drec_val, 0, sizeof(drec_val));
    drec_val.file_id = htole64(new_ino_oid);
    drec_val.flags = htole16(0x1);

    error = apfs_btree_insert_record(&tx, 0, &root_tree_oid,
        drec_key, drec_key_size, &drec_val, sizeof(drec_val));
    free(drec_key);
    if (error != 0) {
        apfs_tx_abort(&tx);
        return error;
    }

    error = apfs_tx_commit(&tx);
    if (error != 0)
        return error;

    if (new_oidp != NULL)
        *new_oidp = new_ino_oid;

    return 0;
}

int
apfs_write_file_extent(struct apfsmount *amp, oid_t ino_oid, uint64_t file_offset,
    uint64_t length, apfs_paddr_t paddr)
{
    apfs_tx_t tx;
    oid_t root_tree_oid;
    j_extent_key_t ext_key;
    j_phys_ext_val_t ext_val;
    int error;

    error = apfs_tx_begin(amp, &tx);
    if (error != 0)
        return error;

    apfs_paddr_t tree_root_paddr;
    error = apfs_tx_alloc_block(&tx, 1, &tree_root_paddr);
    if (error != 0) {
        apfs_tx_abort(&tx);
        return error;
    }
    struct buf *root_bp;
    error = apfs_getblk(amp, tree_root_paddr, &root_bp);
    if (error != 0) {
        apfs_tx_abort(&tx);
        return error;
    }
    btree_node_phys_t *rnode = (btree_node_phys_t *)root_bp->b_data;
    memset(rnode, 0, amp->am_block_size);
    rnode->btn_flags = htole16(BTNODE_ROOT | BTNODE_LEAF);
    btree_info_t *rinfo = (btree_info_t *)((char *)rnode + amp->am_block_size - sizeof(btree_info_t));
    rinfo->bt_flags = htole32(BTREE_PHYSICAL);
    rinfo->bt_node_size = htole32(amp->am_block_size);
    apfs_obj_init(&rnode->btn_o, (oid_t)tree_root_paddr, tx.tx_xid,
        OBJ_BTREE_NODE | OBJ_PHYSICAL, 0);
    apfs_obj_set_cksum(amp, rnode);
    error = apfs_bwrite(amp, tree_root_paddr, root_bp);
    if (error != 0) {
        apfs_tx_abort(&tx);
        return error;
    }
    root_tree_oid = tree_root_paddr;

    ext_key.hdr.obj_id_and_type = htole64((ino_oid & OBJ_ID_MASK) |
        ((uint64_t)APFS_TYPE_EXTENT << OBJ_TYPE_SHIFT));
    ext_key.logical_addr = htole64(file_offset);

    ext_val.len_and_flags = htole64(length & J_EXT_LEN_MASK);
    ext_val.phys_block_num = htole64((uint64_t)paddr);
    ext_val.crypto_id = 0;

    error = apfs_btree_insert_record(&tx, 0, &root_tree_oid,
        &ext_key, sizeof(ext_key), &ext_val, sizeof(ext_val));
    if (error != 0) {
        apfs_tx_abort(&tx);
        return error;
    }

    return apfs_tx_commit(&tx);
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
    apfs_exclusion_table_t excl_table;
    uint64_t block_count, chunk_count, expected_cib_count;
    uint64_t total_free = 0;
    uint64_t first_clear_free = 0, first_set_free = 0;
    uint64_t first_clear_bitmap = 0, first_set_bitmap = 0;
    uint64_t first_clear_chunk = 0, first_set_chunk = 0;
    uint64_t ip_block_count, fs_reserve_block_count, fs_reserve_alloc_count;
    uint64_t active_fq_entries = 0;
    uint32_t first_clear_bit = 0, first_set_bit = 0;
    uint32_t blocks_per_chunk, chunks_per_cib, cib_count, addr_offset;
    uint32_t struct_size, ip_bm_size_in_blocks, ip_bm_block_count;
    apfs_paddr_t ip_bm_base, ip_base;
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
        struct_size > amp->am_block_size ||
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

    error = apfs_build_container_exclusions(amp, &excl_table);
    if (error != 0) {
        brelse(smbp, 0);
        return error;
    }

    ip_block_count = le64toh(sm->sm_ip_block_count);
    ip_bm_size_in_blocks = le32toh(sm->sm_ip_bm_size_in_blocks);
    (void)ip_bm_size_in_blocks;
    ip_bm_block_count = le32toh(sm->sm_ip_bm_block_count);
    ip_bm_base = (apfs_paddr_t)le64toh((uint64_t)sm->sm_ip_bm_base);
    ip_base = (apfs_paddr_t)le64toh((uint64_t)sm->sm_ip_base);
    fs_reserve_block_count = le64toh(sm->sm_fs_reserve_block_count);
    fs_reserve_alloc_count = le64toh(sm->sm_fs_reserve_alloc_count);

    if (ip_block_count > 0) {
        if (ip_base <= 0 || !apfs_range_valid(amp, (uint64_t)ip_base, ip_block_count)) {
            printf("apfs_spaceman: invalid internal pool range (base %lld, count %llu)\n",
                (long long)ip_base, (unsigned long long)ip_block_count);
            brelse(smbp, 0);
            return EINVAL;
        }
        error = apfs_exclusion_add(amp, &excl_table, (uint64_t)ip_base,
            ip_block_count, "internal pool data");
        if (error != 0) {
            brelse(smbp, 0);
            return error;
        }
    }
    if (ip_bm_block_count > 0) {
        if (ip_bm_base <= 0 || !apfs_range_valid(amp, (uint64_t)ip_bm_base, (uint64_t)ip_bm_block_count)) {
            printf("apfs_spaceman: invalid internal pool bitmap range (base %lld, count %u)\n",
                (long long)ip_bm_base, ip_bm_block_count);
            brelse(smbp, 0);
            return EINVAL;
        }
        error = apfs_exclusion_add(amp, &excl_table, (uint64_t)ip_bm_base,
            (uint64_t)ip_bm_block_count, "internal pool bitmap");
        if (error != 0) {
            brelse(smbp, 0);
            return error;
        }
    }
    if (fs_reserve_alloc_count > fs_reserve_block_count) {
        printf("apfs_spaceman: invalid fs reserve (alloc %llu > count %llu)\n",
            (unsigned long long)fs_reserve_alloc_count,
            (unsigned long long)fs_reserve_block_count);
        brelse(smbp, 0);
        return EINVAL;
    }

    for (int q = 0; q < 3; q++) {
        uint64_t sfq_count = le64toh(sm->sm_fq[q].sfq_count);
        oid_t sfq_tree_oid = le64toh(sm->sm_fq[q].sfq_tree_oid);
        xid_t sfq_oldest_xid = le64toh(sm->sm_fq[q].sfq_oldest_xid);

        if (sfq_count > 0) {
            active_fq_entries += sfq_count;
            if (sfq_tree_oid == 0 || sfq_oldest_xid > amp->am_checkpoint_xid) {
                printf("apfs_spaceman: invalid active free queue %d "
                    "(count %llu, tree OID 0x%llx, oldest xid 0x%llx)\n",
                    q, (unsigned long long)sfq_count,
                    (unsigned long long)sfq_tree_oid,
                    (unsigned long long)sfq_oldest_xid);
                brelse(smbp, 0);
                return EINVAL;
            }
        } else if (sfq_tree_oid != 0 && sfq_oldest_xid > amp->am_checkpoint_xid) {
            printf("apfs_spaceman: invalid free queue %d xid "
                "(oldest xid 0x%llx > checkpoint xid 0x%llx)\n",
                q, (unsigned long long)sfq_oldest_xid,
                (unsigned long long)amp->am_checkpoint_xid);
            brelse(smbp, 0);
            return EINVAL;
        }
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
                    uint64_t block_paddr = chunk_start + bit;
                    bool is_safe = apfs_spaceman_candidate_safe(amp,
                        &excl_table, block_paddr);

                    if ((bitmap[bit >> 3] & (1U << (bit & 7))) == 0) {
                        if (first_clear == expected_blocks && is_safe)
                            first_clear = bit;
                        clear_blocks++;
                    } else {
                        if (first_set == expected_blocks && is_safe)
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
    if (active_fq_entries > 0) {
        printf("apfs_spaceman: active free queues contain %llu delayed free entries\n",
            (unsigned long long)active_fq_entries);
    }

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

    apfs_resv_init(amp);

    error = apfs_select_checkpoint(amp);
    if (error != 0) {
        printf("apfs_select_checkpoint failed: %d\n", error);
        apfs_resv_destroy(amp);
        close(test_fd);
        return error;
    }

    return 0;
}

static void
cleanup_mount(struct apfsmount *amp)
{
    apfs_resv_destroy(amp);
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

static void
mod_corrupt_internal_pool_out_of_bounds(uint8_t *buf, size_t size __unused, struct apfsmount *amp)
{
    apfs_paddr_t sm_paddr;
    apfs_checkpoint_lookup(amp, le64toh(amp->am_nx.nx_spaceman_oid), 0, &sm_paddr);
    spaceman_phys_t *sm = (spaceman_phys_t *)(buf + sm_paddr * amp->am_block_size);
    sm->sm_ip_block_count = htole64(100);
    sm->sm_ip_base = htole64(le64toh(amp->am_nx.nx_block_count) + 50);
    recalculate_checksum(sm, amp->am_block_size);
}

static void
mod_corrupt_free_queue_oid_zero(uint8_t *buf, size_t size __unused, struct apfsmount *amp)
{
    apfs_paddr_t sm_paddr;
    apfs_checkpoint_lookup(amp, le64toh(amp->am_nx.nx_spaceman_oid), 0, &sm_paddr);
    spaceman_phys_t *sm = (spaceman_phys_t *)(buf + sm_paddr * amp->am_block_size);
    sm->sm_fq[0].sfq_count = htole64(10);
    sm->sm_fq[0].sfq_tree_oid = 0;
    recalculate_checksum(sm, amp->am_block_size);
}

static void
mod_corrupt_free_queue_xid_future(uint8_t *buf, size_t size __unused, struct apfsmount *amp)
{
    apfs_paddr_t sm_paddr;
    apfs_checkpoint_lookup(amp, le64toh(amp->am_nx.nx_spaceman_oid), 0, &sm_paddr);
    spaceman_phys_t *sm = (spaceman_phys_t *)(buf + sm_paddr * amp->am_block_size);
    sm->sm_fq[0].sfq_count = htole64(10);
    sm->sm_fq[0].sfq_tree_oid = htole64(1024);
    sm->sm_fq[0].sfq_oldest_xid = htole64(amp->am_checkpoint_xid + 9999);
    recalculate_checksum(sm, amp->am_block_size);
}

static void
mod_overlapping_checkpoint_rings(uint8_t *buf __unused, size_t size __unused, struct apfsmount *amp)
{
    /* Overlap descriptor and data rings */
    amp->am_nx.nx_xp_data_base = amp->am_nx.nx_xp_desc_base;
    amp->am_nx.nx_xp_data_blocks = amp->am_nx.nx_xp_desc_blocks;
}

static void
mod_internal_pool_valid(uint8_t *buf, size_t size __unused, struct apfsmount *amp)
{
    apfs_paddr_t sm_paddr;
    apfs_checkpoint_lookup(amp, le64toh(amp->am_nx.nx_spaceman_oid), 0, &sm_paddr);
    spaceman_phys_t *sm = (spaceman_phys_t *)(buf + sm_paddr * amp->am_block_size);
    uint64_t total_blocks = le64toh(amp->am_nx.nx_block_count);
    sm->sm_ip_block_count = htole64(50);
    sm->sm_ip_base = htole64(total_blocks - 100);
    sm->sm_ip_bm_block_count = htole32(2);
    sm->sm_ip_bm_base = htole64(total_blocks - 40);
    recalculate_checksum(sm, amp->am_block_size);
}

static void
test_exclusion_range_helpers(void)
{
    struct apfsmount amp;
    apfs_exclusion_table_t table;
    int error;

    memset(&amp, 0, sizeof(amp));
    amp.am_nx.nx_block_count = htole64(1000);
    amp.am_nx.nx_xp_desc_base = htole64(10);
    amp.am_nx.nx_xp_desc_blocks = htole32(20);
    amp.am_nx.nx_xp_data_base = htole64(50);
    amp.am_nx.nx_xp_data_blocks = htole32(30);

    /* Test build exclusions */
    error = apfs_build_container_exclusions(&amp, &table);
    assert(error == 0);
    assert(table.aet_count == 3);

    /* Block 0, ring 10..29, ring 50..79 are excluded */
    assert(!apfs_spaceman_candidate_safe(&amp, &table, 0));
    assert(!apfs_spaceman_candidate_safe(&amp, &table, 10));
    assert(!apfs_spaceman_candidate_safe(&amp, &table, 25));
    assert(!apfs_spaceman_candidate_safe(&amp, &table, 29));
    assert(!apfs_spaceman_candidate_safe(&amp, &table, 50));
    assert(!apfs_spaceman_candidate_safe(&amp, &table, 79));

    /* Unreserved blocks are safe */
    assert(apfs_spaceman_candidate_safe(&amp, &table, 1));
    assert(apfs_spaceman_candidate_safe(&amp, &table, 9));
    assert(apfs_spaceman_candidate_safe(&amp, &table, 30));
    assert(apfs_spaceman_candidate_safe(&amp, &table, 49));
    assert(apfs_spaceman_candidate_safe(&amp, &table, 80));
    assert(apfs_spaceman_candidate_safe(&amp, &table, 999));

    /* Out of bounds blocks are rejected */
    assert(!apfs_spaceman_candidate_safe(&amp, &table, 1000));
    assert(!apfs_spaceman_candidate_safe(&amp, &table, 1050));

    /* Overlapping range fails closed */
    error = apfs_exclusion_add(&amp, &table, 20, 15, "overlapping range");
    assert(error == EINVAL);

    /* Out-of-bounds range fails closed */
    error = apfs_exclusion_add(&amp, &table, 950, 100, "out of bounds range");
    assert(error == EINVAL);
}

static void
test_sequential_batch_allocation(const char *image_path)
{
    struct apfsmount amp;
    apfs_exclusion_table_t excl_table;
    int error;

    error = init_mount(image_path, &amp);
    assert(error == 0);

    error = apfs_build_container_exclusions(&amp, &excl_table);
    assert(error == 0);

    /* 1. Allocate 50 single blocks sequentially */
    uint64_t addrs[50];
    for (int i = 0; i < 50; i++) {
        apfs_paddr_t paddr = 0;
        error = apfs_resv_alloc(&amp, NULL, 1, &paddr);
        assert(error == 0);
        assert(paddr > 0);
        assert(apfs_spaceman_candidate_safe(&amp, &excl_table, (uint64_t)paddr));
        assert(apfs_resv_is_reserved(&amp, (uint64_t)paddr, 1));

        /* Verify uniqueness */
        for (int j = 0; j < i; j++) {
            assert(addrs[j] != (uint64_t)paddr);
        }
        addrs[i] = (uint64_t)paddr;
    }

    assert(amp.am_resv_pool.rp_total_reserved == 50);

    /* 2. Allocate multi-block spans (e.g. 4, 8, 16) */
    apfs_paddr_t span4 = 0, span8 = 0, span16 = 0;
    error = apfs_resv_alloc(&amp, NULL, 4, &span4);
    assert(error == 0);
    for (uint64_t b = 0; b < 4; b++) {
        assert(apfs_spaceman_candidate_safe(&amp, &excl_table, (uint64_t)span4 + b));
        for (int i = 0; i < 50; i++) {
            assert(addrs[i] != (uint64_t)span4 + b);
        }
    }

    error = apfs_resv_alloc(&amp, NULL, 8, &span8);
    assert(error == 0);
    for (uint64_t b = 0; b < 8; b++) {
        assert(apfs_spaceman_candidate_safe(&amp, &excl_table, (uint64_t)span8 + b));
        for (int i = 0; i < 50; i++) {
            assert(addrs[i] != (uint64_t)span8 + b);
        }
        assert((uint64_t)span8 + b < (uint64_t)span4 || (uint64_t)span8 + b >= (uint64_t)span4 + 4);
    }

    error = apfs_resv_alloc(&amp, NULL, 16, &span16);
    assert(error == 0);
    assert(amp.am_resv_pool.rp_total_reserved == 50 + 4 + 8 + 16);

    cleanup_mount(&amp);
}

typedef struct thread_worker_arg {
    struct apfsmount *amp;
    uint64_t tx_id;
    int count;
    uint64_t *out_addrs;
} thread_worker_arg_t;

static void *
alloc_worker_thread(void *arg)
{
    thread_worker_arg_t *warg = (thread_worker_arg_t *)arg;
    apfs_resv_tx_t tx;
    tx.rt_tx_id = warg->tx_id;
    tx.rt_count = 0;
    LIST_INIT(&tx.rt_entries);

    for (int i = 0; i < warg->count; i++) {
        apfs_paddr_t paddr = 0;
        int error = apfs_resv_alloc(warg->amp, &tx, 1, &paddr);
        assert(error == 0);
        warg->out_addrs[i] = (uint64_t)paddr;
    }
    return NULL;
}

static void
test_concurrent_allocation_contention(const char *image_path)
{
    struct apfsmount amp;
    int error;

    error = init_mount(image_path, &amp);
    assert(error == 0);

    const int num_threads = 8;
    const int per_thread = 25;
    pthread_t threads[8];
    thread_worker_arg_t args[8];
    uint64_t thread_addrs[8][25];

    for (int t = 0; t < num_threads; t++) {
        args[t].amp = &amp;
        args[t].tx_id = 5000 + t;
        args[t].count = per_thread;
        args[t].out_addrs = thread_addrs[t];
        pthread_create(&threads[t], NULL, alloc_worker_thread, &args[t]);
    }

    for (int t = 0; t < num_threads; t++) {
        pthread_join(threads[t], NULL);
    }

    assert(amp.am_resv_pool.rp_total_reserved == (uint64_t)(num_threads * per_thread));

    /* Verify all 200 allocated blocks are mutually distinct */
    uint64_t all_addrs[200];
    int idx = 0;
    for (int t = 0; t < num_threads; t++) {
        for (int i = 0; i < per_thread; i++) {
            uint64_t a = thread_addrs[t][i];
            for (int k = 0; k < idx; k++) {
                assert(all_addrs[k] != a);
            }
            all_addrs[idx++] = a;
        }
    }

    cleanup_mount(&amp);
}

static void
test_transaction_rollback_and_abort(const char *image_path)
{
    struct apfsmount amp;
    int error;

    error = init_mount(image_path, &amp);
    assert(error == 0);

    apfs_resv_tx_t tx;
    tx.rt_tx_id = 999;
    tx.rt_count = 0;
    LIST_INIT(&tx.rt_entries);

    apfs_paddr_t first_paddr = 0;
    error = apfs_resv_alloc(&amp, &tx, 1, &first_paddr);
    assert(error == 0);
    assert(tx.rt_count == 1);
    assert(amp.am_resv_pool.rp_total_reserved == 1);

    for (int i = 1; i < 20; i++) {
        apfs_paddr_t paddr = 0;
        error = apfs_resv_alloc(&amp, &tx, 1, &paddr);
        assert(error == 0);
    }
    assert(tx.rt_count == 20);
    assert(amp.am_resv_pool.rp_total_reserved == 20);

    /* Abort transaction */
    apfs_resv_abort(&amp, &tx);
    assert(tx.rt_count == 0);
    assert(amp.am_resv_pool.rp_total_reserved == 0);
    assert(!apfs_resv_is_reserved(&amp, (uint64_t)first_paddr, 1));

    /* Reset roving cursor to 0 and verify candidate block is immediately re-acquired */
    amp.am_resv_pool.rp_last_chunk = 0;
    amp.am_resv_pool.rp_last_bit = 0;

    apfs_paddr_t new_paddr = 0;
    error = apfs_resv_alloc(&amp, NULL, 1, &new_paddr);
    assert(error == 0);
    assert(new_paddr == first_paddr);

    cleanup_mount(&amp);
}

static void
test_enospc_exhaustion(const char *image_path)
{
    struct apfsmount amp;
    int error;

    error = init_mount(image_path, &amp);
    assert(error == 0);

    apfs_resv_tx_t tx;
    tx.rt_tx_id = 777;
    tx.rt_count = 0;
    LIST_INIT(&tx.rt_entries);

    /* Allocate until capacity is exhausted */
    int alloc_count = 0;
    while (1) {
        apfs_paddr_t paddr = 0;
        error = apfs_resv_alloc(&amp, &tx, 64, &paddr);
        if (error == ENOSPC) {
            error = apfs_resv_alloc(&amp, &tx, 1, &paddr);
            if (error == ENOSPC)
                break;
        }
        assert(error == 0);
        alloc_count++;
        if (alloc_count > 200000) break;
    }

    assert(error == ENOSPC);
    printf("  (exhausted capacity after reserving %llu blocks)\n",
        (unsigned long long)amp.am_resv_pool.rp_total_reserved);

    /* Abort all reservations */
    apfs_resv_abort(&amp, &tx);
    assert(amp.am_resv_pool.rp_total_reserved == 0);

    /* Subsequent allocation succeeds */
    apfs_paddr_t post_paddr = 0;
    error = apfs_resv_alloc(&amp, NULL, 1, &post_paddr);
    assert(error == 0);
    assert(post_paddr > 0);

    cleanup_mount(&amp);
}

static void
test_resv_free_and_alloc_block(const char *image_path)
{
    struct apfsmount amp;
    apfs_paddr_t paddr1 = 0, paddr2 = 0;
    int error;

    error = init_mount(image_path, &amp);
    assert(error == 0);

    error = apfs_alloc_block(&amp, &paddr1);
    assert(error == 0);
    error = apfs_alloc_block(&amp, &paddr2);
    assert(error == 0);
    assert(paddr1 != paddr2);
    assert(amp.am_resv_pool.rp_total_reserved == 2);

    error = apfs_free_block(&amp, paddr1);
    assert(error == 0);
    assert(!apfs_resv_is_reserved(&amp, (uint64_t)paddr1, 1));
    assert(apfs_resv_is_reserved(&amp, (uint64_t)paddr2, 1));
    assert(amp.am_resv_pool.rp_total_reserved == 1);

    error = apfs_free_block(&amp, paddr2);
    assert(error == 0);
    assert(amp.am_resv_pool.rp_total_reserved == 0);

    cleanup_mount(&amp);
}

static void
test_tx_lifecycle_and_cow_alloc(const char *image_path)
{
    struct apfsmount amp;
    apfs_tx_t tx;
    apfs_paddr_t paddr = 0;
    struct buf *bp = NULL;
    int error;

    error = init_mount(image_path, &amp);
    assert(error == 0);

    /* 1. Begin transaction */
    error = apfs_tx_begin(&amp, &tx);
    assert(error == 0);
    assert(tx.tx_xid == amp.am_checkpoint_xid + 1);
    assert(tx.tx_state == APFS_TX_STATE_ACTIVE);
    assert(tx.tx_map_count == 0);

    /* 2. Allocate candidate block */
    error = apfs_tx_alloc_block(&tx, 1, &paddr);
    assert(error == 0);
    assert(paddr > 0);
    assert(tx.tx_resv.rt_count == 1);
    assert(amp.am_resv_pool.rp_total_reserved >= 1);

    /* 3. Initialize header, sign checksum, verify */
    error = apfs_getblk(&amp, paddr, &bp);
    assert(error == 0);
    assert(bp != NULL);

    apfs_obj_init((obj_phys_t *)bp->b_data, 0x12345, tx.tx_xid,
        OBJ_BTREE_NODE | OBJ_PHYSICAL, 0);
    apfs_obj_set_cksum(&amp, bp->b_data);
    assert(apfs_checksum_valid(&amp, bp->b_data));

    brelse(bp, 0);

    /* 4. Abort transaction */
    apfs_tx_abort(&tx);
    assert(tx.tx_state == APFS_TX_STATE_ABORTED);
    assert(tx.tx_resv.rt_count == 0);
    assert(amp.am_resv_pool.rp_total_reserved == 0);

    cleanup_mount(&amp);
}

static void
test_tx_commit_and_checkpoint_resolution(const char *image_path)
{
    struct apfsmount amp;
    apfs_tx_t tx;
    apfs_paddr_t cow_paddr = 0, resolved_paddr = 0;
    struct buf *bp = NULL;
    int fd, error;
    struct stat st;

    fd = open(image_path, O_RDONLY);
    assert(fd >= 0);
    fstat(fd, &st);
    synthetic_buffer_size = st.st_size;
    synthetic_buffer = malloc(synthetic_buffer_size);
    assert(synthetic_buffer != NULL);
    ssize_t n = read(fd, synthetic_buffer, synthetic_buffer_size);
    assert(n == (ssize_t)synthetic_buffer_size);
    close(fd);

    memset(&amp, 0, sizeof(amp));
    nx_superblock_t *nx = (nx_superblock_t *)synthetic_buffer;
    amp.am_block_size = le32toh(nx->nx_block_size);
    memcpy(&amp.am_nx, nx, sizeof(*nx));
    apfs_resv_init(&amp);

    /* Select initial checkpoint */
    error = apfs_select_checkpoint(&amp);
    assert(error == 0);
    xid_t initial_xid = amp.am_checkpoint_xid;

    /* Begin transaction */
    error = apfs_tx_begin(&amp, &tx);
    assert(error == 0);
    assert(tx.tx_xid == initial_xid + 1);

    /* Allocate COW block for ephemeral object (e.g. test FS object OID 0x8888) */
    error = apfs_tx_alloc_block(&tx, 1, &cow_paddr);
    assert(error == 0);

    /* Write ephemeral payload block */
    error = apfs_getblk(&amp, cow_paddr, &bp);
    assert(error == 0);
    memset(bp->b_data, 0xaa, amp.am_block_size);
    apfs_obj_init((obj_phys_t *)bp->b_data, 0x8888, tx.tx_xid,
        OBJ_FS | OBJ_EPHEMERAL, 0);
    apfs_obj_set_cksum(&amp, bp->b_data);
    error = apfs_bwrite_cow(&tx, cow_paddr, bp);
    assert(error == 0);

    /* Register ephemeral mapping */
    error = apfs_tx_add_mapping(&tx, OBJ_FS | OBJ_EPHEMERAL, 0,
        amp.am_block_size, 0, 0x8888, cow_paddr);
    assert(error == 0);

    /* Commit transaction */
    error = apfs_tx_commit(&tx);
    assert(error == 0);
    assert(tx.tx_state == APFS_TX_STATE_COMMITTED);
    assert(amp.am_checkpoint_xid == initial_xid + 1);

    /* Re-run select_checkpoint to verify disk structures were written correctly */
    struct apfsmount remount_amp;
    memset(&remount_amp, 0, sizeof(remount_amp));
    remount_amp.am_block_size = le32toh(nx->nx_block_size);
    memcpy(&remount_amp.am_nx, nx, sizeof(*nx));
    apfs_resv_init(&remount_amp);

    error = apfs_select_checkpoint(&remount_amp);
    assert(error == 0);
    assert(remount_amp.am_checkpoint_xid == initial_xid + 1);

    /* Resolve ephemeral mapping */
    error = apfs_checkpoint_lookup(&remount_amp, 0x8888, 0, &resolved_paddr);
    assert(error == 0);
    assert(resolved_paddr == cow_paddr);

    /* Verify resolved block content and valid checksum */
    error = apfs_bread(&remount_amp, resolved_paddr, &bp);
    assert(error == 0);
    assert(apfs_checksum_valid(&remount_amp, bp->b_data));
    obj_phys_t *obj = (obj_phys_t *)bp->b_data;
    assert(le64toh(obj->o_oid) == 0x8888);
    assert(le64toh(obj->o_xid) == initial_xid + 1);
    brelse(bp, 0);

    apfs_resv_destroy(&amp);
    apfs_resv_destroy(&remount_amp);
    free(synthetic_buffer);
    synthetic_buffer = NULL;
    synthetic_buffer_size = 0;
}

static void
test_tx_abort_zero_disk_mutation(const char *image_path)
{
    struct apfsmount amp;
    apfs_tx_t tx;
    apfs_paddr_t paddr = 0;
    int fd, error;
    struct stat st;

    fd = open(image_path, O_RDONLY);
    assert(fd >= 0);
    fstat(fd, &st);
    synthetic_buffer_size = st.st_size;
    synthetic_buffer = malloc(synthetic_buffer_size);
    uint8_t *snapshot = malloc(synthetic_buffer_size);
    assert(synthetic_buffer != NULL && snapshot != NULL);
    ssize_t n = read(fd, synthetic_buffer, synthetic_buffer_size);
    assert(n == (ssize_t)synthetic_buffer_size);
    memcpy(snapshot, synthetic_buffer, synthetic_buffer_size);
    close(fd);

    memset(&amp, 0, sizeof(amp));
    nx_superblock_t *nx = (nx_superblock_t *)synthetic_buffer;
    amp.am_block_size = le32toh(nx->nx_block_size);
    memcpy(&amp.am_nx, nx, sizeof(*nx));
    apfs_resv_init(&amp);

    error = apfs_select_checkpoint(&amp);
    assert(error == 0);

    /* Begin transaction, allocate, add mapping, then abort */
    error = apfs_tx_begin(&amp, &tx);
    assert(error == 0);

    error = apfs_tx_alloc_block(&tx, 4, &paddr);
    assert(error == 0);

    error = apfs_tx_add_mapping(&tx, OBJ_FS | OBJ_EPHEMERAL, 0,
        amp.am_block_size, 0, 0x7777, paddr);
    assert(error == 0);

    apfs_tx_abort(&tx);
    assert(tx.tx_state == APFS_TX_STATE_ABORTED);
    assert(amp.am_resv_pool.rp_total_reserved == 0);

    /* Disk buffer must be 100% bitwise identical to snapshot */
    assert(memcmp(synthetic_buffer, snapshot, synthetic_buffer_size) == 0);

    apfs_resv_destroy(&amp);
    free(snapshot);
    free(synthetic_buffer);
    synthetic_buffer = NULL;
    synthetic_buffer_size = 0;
}

static void
test_simulated_interrupted_transaction(const char *image_path)
{
    struct apfsmount amp;
    apfs_tx_t tx;
    apfs_paddr_t paddr = 0;
    struct buf *bp = NULL;
    int fd, error;
    struct stat st;

    fd = open(image_path, O_RDONLY);
    assert(fd >= 0);
    fstat(fd, &st);
    synthetic_buffer_size = st.st_size;
    synthetic_buffer = malloc(synthetic_buffer_size);
    assert(synthetic_buffer != NULL);
    ssize_t n = read(fd, synthetic_buffer, synthetic_buffer_size);
    assert(n == (ssize_t)synthetic_buffer_size);
    close(fd);

    memset(&amp, 0, sizeof(amp));
    nx_superblock_t *nx = (nx_superblock_t *)synthetic_buffer;
    amp.am_block_size = le32toh(nx->nx_block_size);
    memcpy(&amp.am_nx, nx, sizeof(*nx));
    apfs_resv_init(&amp);

    error = apfs_select_checkpoint(&amp);
    assert(error == 0);
    xid_t initial_xid = amp.am_checkpoint_xid;

    /* Begin transaction */
    error = apfs_tx_begin(&amp, &tx);
    assert(error == 0);

    /* Allocate and write a payload block */
    error = apfs_tx_alloc_block(&tx, 1, &paddr);
    assert(error == 0);

    error = apfs_getblk(&amp, paddr, &bp);
    assert(error == 0);
    apfs_obj_init((obj_phys_t *)bp->b_data, 0x5555, tx.tx_xid,
        OBJ_FS | OBJ_EPHEMERAL, 0);
    apfs_obj_set_cksum(&amp, bp->b_data);
    error = apfs_bwrite_cow(&tx, paddr, bp);
    assert(error == 0);

    /* Write an incomplete descriptor ring entry (corrupt/invalid superblock at next slot) */
    uint32_t old_desc_index = le32toh(amp.am_nx.nx_xp_desc_index);
    uint32_t old_desc_len = le32toh(amp.am_nx.nx_xp_desc_len);
    uint32_t next_slot = (old_desc_index + old_desc_len) % amp.am_desc_blocks;
    uint64_t desc_base = le64toh(amp.am_nx.nx_xp_desc_base);
    apfs_paddr_t corrupt_paddr = (apfs_paddr_t)(desc_base + next_slot);

    error = apfs_getblk(&amp, corrupt_paddr, &bp);
    assert(error == 0);
    nx_superblock_t *bad_sb = (nx_superblock_t *)bp->b_data;
    memcpy(bad_sb, &amp.am_nx, sizeof(*bad_sb));
    apfs_obj_init(&bad_sb->nx_o, 1, tx.tx_xid,
        OBJ_CONTAINER_SUPERBLOCK | OBJ_PHYSICAL, 0);
    /* Deliberately put bad checksum */
    memset(bad_sb->nx_o.o_cksum, 0xff, sizeof(bad_sb->nx_o.o_cksum));
    error = apfs_bwrite(&amp, corrupt_paddr, bp);
    assert(error == 0);

    /* Simulate crash: Abort in-memory state */
    apfs_tx_abort(&tx);

    /* Remount image and verify that select_checkpoint gracefully falls back to initial_xid */
    struct apfsmount remount_amp;
    memset(&remount_amp, 0, sizeof(remount_amp));
    remount_amp.am_block_size = le32toh(nx->nx_block_size);
    memcpy(&remount_amp.am_nx, nx, sizeof(*nx));
    apfs_resv_init(&remount_amp);

    error = apfs_select_checkpoint(&remount_amp);
    assert(error == 0);
    assert(remount_amp.am_checkpoint_xid == initial_xid);

    apfs_resv_destroy(&amp);
    apfs_resv_destroy(&remount_amp);
    free(synthetic_buffer);
    synthetic_buffer = NULL;
    synthetic_buffer_size = 0;
}

static void
test_tx_spaceman_cow_and_bitmap_commit(const char *image_path)
{
    struct apfsmount amp;
    apfs_tx_t tx;
    apfs_paddr_t p1 = 0, p2 = 0;
    int fd, error;
    struct stat st;

    fd = open(image_path, O_RDONLY);
    assert(fd >= 0);
    fstat(fd, &st);
    synthetic_buffer_size = st.st_size;
    synthetic_buffer = malloc(synthetic_buffer_size);
    assert(synthetic_buffer != NULL);
    ssize_t n = read(fd, synthetic_buffer, synthetic_buffer_size);
    assert(n == (ssize_t)synthetic_buffer_size);
    close(fd);

    memset(&amp, 0, sizeof(amp));
    nx_superblock_t *nx = (nx_superblock_t *)synthetic_buffer;
    amp.am_block_size = le32toh(nx->nx_block_size);
    memcpy(&amp.am_nx, nx, sizeof(*nx));
    apfs_resv_init(&amp);

    error = apfs_select_checkpoint(&amp);
    assert(error == 0);
    xid_t initial_xid = amp.am_checkpoint_xid;

    /* Begin transaction */
    error = apfs_tx_begin(&amp, &tx);
    assert(error == 0);

    /* Allocate physical blocks */
    error = apfs_tx_alloc_block(&tx, 2, &p1);
    assert(error == 0);
    error = apfs_tx_alloc_block(&tx, 3, &p2);
    assert(error == 0);

    /* Commit transaction */
    error = apfs_tx_commit(&tx);
    assert(error == 0);
    assert(tx.tx_state == APFS_TX_STATE_COMMITTED);

    /* Remount and validate Space Manager */
    struct apfsmount remount_amp;
    memset(&remount_amp, 0, sizeof(remount_amp));
    remount_amp.am_block_size = le32toh(nx->nx_block_size);
    memcpy(&remount_amp.am_nx, nx, sizeof(*nx));
    apfs_resv_init(&remount_amp);

    error = apfs_select_checkpoint(&remount_amp);
    assert(error == 0);
    assert(remount_amp.am_checkpoint_xid == initial_xid + 1);

    error = apfs_validate_spaceman(&remount_amp);
    assert(error == 0);

    apfs_resv_destroy(&amp);
    apfs_resv_destroy(&remount_amp);
    free(synthetic_buffer);
    synthetic_buffer = NULL;
    synthetic_buffer_size = 0;
}

static void
test_btree_cow_insert_and_search(const char *image_path)
{
    struct apfsmount amp;
    apfs_tx_t tx;
    oid_t tree_oid = 0;
    int fd, error;
    struct stat st;

    fd = open(image_path, O_RDONLY);
    assert(fd >= 0);
    fstat(fd, &st);
    synthetic_buffer_size = st.st_size;
    synthetic_buffer = malloc(synthetic_buffer_size);
    assert(synthetic_buffer != NULL);
    ssize_t n = read(fd, synthetic_buffer, synthetic_buffer_size);
    assert(n == (ssize_t)synthetic_buffer_size);
    close(fd);

    memset(&amp, 0, sizeof(amp));
    nx_superblock_t *nx = (nx_superblock_t *)synthetic_buffer;
    amp.am_block_size = le32toh(nx->nx_block_size);
    memcpy(&amp.am_nx, nx, sizeof(*nx));
    apfs_resv_init(&amp);

    error = apfs_select_checkpoint(&amp);
    assert(error == 0);

    error = apfs_tx_begin(&amp, &tx);
    assert(error == 0);

    /* Allocate empty root btree node */
    apfs_paddr_t root_paddr;
    error = apfs_tx_alloc_block(&tx, 1, &root_paddr);
    assert(error == 0);

    struct buf *bp;
    error = apfs_getblk(&amp, root_paddr, &bp);
    assert(error == 0);
    btree_node_phys_t *rnode = (btree_node_phys_t *)bp->b_data;
    memset(rnode, 0, amp.am_block_size);
    rnode->btn_flags = htole16(BTNODE_ROOT | BTNODE_LEAF);
    btree_info_t *rinfo = (btree_info_t *)((char *)rnode + amp.am_block_size - sizeof(btree_info_t));
    rinfo->bt_flags = htole32(BTREE_PHYSICAL);
    rinfo->bt_node_size = htole32(amp.am_block_size);
    apfs_obj_init(&rnode->btn_o, (oid_t)root_paddr, tx.tx_xid, OBJ_BTREE_NODE | OBJ_PHYSICAL, 0);
    apfs_obj_set_cksum(&amp, rnode);
    error = apfs_bwrite(&amp, root_paddr, bp);
    assert(error == 0);
    tree_oid = root_paddr;

    /* Insert records in arbitrary order */
    uint64_t oids[] = { 0x300, 0x100, 0x500, 0x200, 0x400 };
    for (int i = 0; i < 5; i++) {
        j_key_t key;
        key.obj_id_and_type = htole64((oids[i] & OBJ_ID_MASK) | ((uint64_t)APFS_TYPE_INODE << OBJ_TYPE_SHIFT));
        j_inode_val_t val;
        memset(&val, 0, sizeof(val));
        val.private_id = htole64(oids[i]);
        val.owner = htole32(1000 + i);

        error = apfs_btree_insert_record(&tx, 0, &tree_oid, &key, sizeof(key), &val, sizeof(val));
        assert(error == 0);
    }

    error = apfs_tx_commit(&tx);
    assert(error == 0);

    /* Verify on disk */
    error = apfs_bread(&amp, (apfs_paddr_t)tree_oid, &bp);
    assert(error == 0);
    btree_node_phys_t *chk_node = (btree_node_phys_t *)bp->b_data;
    assert(apfs_checksum_valid(&amp, chk_node));
    assert(le32toh(chk_node->btn_nkeys) == 5);

    /* Verify sorted order */
    uint64_t prev_id = 0;
    btree_info_t info;
    memcpy(&info, (char *)chk_node + amp.am_block_size - sizeof(info), sizeof(info));
    for (uint32_t i = 0; i < 5; i++) {
        const void *k_ptr, *v_ptr;
        size_t k_len, v_len;
        error = apfs_btree_entry(&amp, chk_node, &info, i, &k_ptr, &k_len, &v_ptr, &v_len);
        assert(error == 0);
        const j_key_t *jk = k_ptr;
        uint64_t id = le64toh(jk->obj_id_and_type) & OBJ_ID_MASK;
        assert(id > prev_id);
        prev_id = id;
    }
    brelse(bp, 0);

    apfs_resv_destroy(&amp);
    free(synthetic_buffer);
    synthetic_buffer = NULL;
    synthetic_buffer_size = 0;
}

static void
test_file_creation_and_extent_writes(const char *image_path)
{
    struct apfsmount amp;
    oid_t new_file_oid = 0;
    int fd, error;
    struct stat st;

    fd = open(image_path, O_RDONLY);
    assert(fd >= 0);
    fstat(fd, &st);
    synthetic_buffer_size = st.st_size;
    synthetic_buffer = malloc(synthetic_buffer_size);
    assert(synthetic_buffer != NULL);
    ssize_t n = read(fd, synthetic_buffer, synthetic_buffer_size);
    assert(n == (ssize_t)synthetic_buffer_size);
    close(fd);

    memset(&amp, 0, sizeof(amp));
    nx_superblock_t *nx = (nx_superblock_t *)synthetic_buffer;
    amp.am_block_size = le32toh(nx->nx_block_size);
    memcpy(&amp.am_nx, nx, sizeof(*nx));
    apfs_resv_init(&amp);

    error = apfs_select_checkpoint(&amp);
    assert(error == 0);

    /* Create file */
    error = apfs_create_file(&amp, 0x1, "testfile.dat", 0644, 501, 20, &new_file_oid);
    assert(error == 0);
    assert(new_file_oid != 0);

    /* Write file extent */
    error = apfs_write_file_extent(&amp, new_file_oid, 0, 4096, 500);
    assert(error == 0);

    /* Validate spaceman after writes */
    struct apfsmount remount_amp;
    memset(&remount_amp, 0, sizeof(remount_amp));
    remount_amp.am_block_size = le32toh(nx->nx_block_size);
    memcpy(&remount_amp.am_nx, nx, sizeof(*nx));
    apfs_resv_init(&remount_amp);

    error = apfs_select_checkpoint(&remount_amp);
    assert(error == 0);

    error = apfs_validate_spaceman(&remount_amp);
    assert(error == 0);

    apfs_resv_destroy(&amp);
    apfs_resv_destroy(&remount_amp);
    free(synthetic_buffer);
    synthetic_buffer = NULL;
    synthetic_buffer_size = 0;
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

    /* 0. Unit Tests for Exclusion Range Helpers */
    printf("\n--- Test Case: Container Exclusion Range Calculation & Safety Filter ---\n");
    test_exclusion_range_helpers();
    printf("PASS: Exclusion range calculation and candidate safety filter verified\n");

    /* 1. Real Image Tests */
    const char *test_images[] = {
        "/tmp/apfs_test_images/fresh_50m.dmg",
        "/tmp/apfs_test_images/populated_100m.dmg",
        "/tmp/apfs_test_images/deleted_120m.dmg",
        "/tmp/apfs_test_images/multichunk_300m.dmg"
    };

    for (size_t i = 0; i < sizeof(test_images)/sizeof(test_images[0]); i++) {
        if (access(test_images[i], F_OK) != 0)
            continue;
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

    /* 7. Valid Internal Pool Layout */
    printf("\n--- Test Case: Valid Internal Pool Layout ---\n");
    error = run_synthetic_test(mod_internal_pool_valid);
    assert(error == 0);
    printf("PASS: Valid internal pool registered into exclusion table and verified\n");

    /* 8. Corrupt Out-of-Bounds Internal Pool (Fail-Closed) */
    printf("\n--- Test Case: Corrupt Out-of-Bounds Internal Pool (Fail-Closed) ---\n");
    error = run_synthetic_test(mod_corrupt_internal_pool_out_of_bounds);
    assert(error == EINVAL);
    printf("PASS: Out-of-bounds internal pool rejected with EINVAL\n");

    /* 9. Corrupt Free Queue OID Zero (Fail-Closed) */
    printf("\n--- Test Case: Corrupt Free Queue OID Zero (Fail-Closed) ---\n");
    error = run_synthetic_test(mod_corrupt_free_queue_oid_zero);
    assert(error == EINVAL);
    printf("PASS: Active free queue with zero OID rejected with EINVAL\n");

    /* 10. Corrupt Free Queue Future XID (Fail-Closed) */
    printf("\n--- Test Case: Corrupt Free Queue Future XID (Fail-Closed) ---\n");
    error = run_synthetic_test(mod_corrupt_free_queue_xid_future);
    assert(error == EINVAL);
    printf("PASS: Free queue with future transaction ID rejected with EINVAL\n");

    /* 11. Overlapping Checkpoint Rings (Fail-Closed) */
    printf("\n--- Test Case: Overlapping Checkpoint Rings (Fail-Closed) ---\n");
    error = run_synthetic_test(mod_overlapping_checkpoint_rings);
    assert(error == EINVAL);
    printf("PASS: Overlapping checkpoint rings rejected with EINVAL\n");

    /* 12. Milestone 3: In-Memory Reservation & Allocation Tests */
    for (size_t i = 0; i < sizeof(test_images)/sizeof(test_images[0]); i++) {
        if (access(test_images[i], F_OK) != 0)
            continue;
        printf("\n--- Test Case: Sequential & Multi-Block Span Reservation (%s) ---\n", test_images[i]);
        test_sequential_batch_allocation(test_images[i]);
        printf("PASS: Sequential and multi-block span reservation verified\n");

        printf("\n--- Test Case: Concurrent Allocation Contention (%s) ---\n", test_images[i]);
        test_concurrent_allocation_contention(test_images[i]);
        printf("PASS: Multi-threaded concurrent allocation verified with zero duplicates\n");

        printf("\n--- Test Case: Transaction Rollback and Abort (%s) ---\n", test_images[i]);
        test_transaction_rollback_and_abort(test_images[i]);
        printf("PASS: Transaction rollback and abort verified without leaking reservations\n");

        printf("\n--- Test Case: Block Free and Wrapper Stubs (%s) ---\n", test_images[i]);
        test_resv_free_and_alloc_block(test_images[i]);
        printf("PASS: Block free and allocator wrapper stubs verified\n");
    }

    if (access(test_images[0], F_OK) == 0) {
        printf("\n--- Test Case: Out-of-Space (ENOSPC) Capacity Exhaustion ---\n");
        test_enospc_exhaustion(test_images[0]);
        printf("PASS: Out-of-space exhaustion and recovery verified cleanly\n");
    }

    /* 13. Milestone 4: Transaction & Copy-on-Write Tests */
    for (size_t i = 0; i < sizeof(test_images)/sizeof(test_images[0]); i++) {
        if (access(test_images[i], F_OK) != 0)
            continue;
        printf("\n--- Test Case: Transaction Lifecycle & COW Block Allocation (%s) ---\n", test_images[i]);
        test_tx_lifecycle_and_cow_alloc(test_images[i]);
        printf("PASS: Transaction lifecycle and COW block allocation verified\n");

        printf("\n--- Test Case: Checkpoint Publishing & Remount Resolution (%s) ---\n", test_images[i]);
        test_tx_commit_and_checkpoint_resolution(test_images[i]);
        printf("PASS: Checkpoint publishing and ephemeral mapping resolution verified\n");

        printf("\n--- Test Case: Transaction Abort Bitwise Zero-Disk-Mutation (%s) ---\n", test_images[i]);
        test_tx_abort_zero_disk_mutation(test_images[i]);
        printf("PASS: Transaction abort leaves disk 100%% bitwise identical\n");

        printf("\n--- Test Case: Simulated Interrupted Transaction Recovery (%s) ---\n", test_images[i]);
        test_simulated_interrupted_transaction(test_images[i]);
        printf("PASS: Interrupted transaction cleanly recovers prior checkpoint\n");
    }

    /* 14. Milestone 5: Space Manager Transactional Updates & Bitmap COW */
    for (size_t i = 0; i < sizeof(test_images)/sizeof(test_images[0]); i++) {
        if (access(test_images[i], F_OK) != 0)
            continue;
        printf("\n--- Test Case: Space Manager COW & Bitmap Commit (%s) ---\n", test_images[i]);
        test_tx_spaceman_cow_and_bitmap_commit(test_images[i]);
        printf("PASS: Space Manager COW and allocation bitmap commit verified\n");
    }

    /* 15. Milestone 6: B-Tree COW Insertion & Sorted Search */
    for (size_t i = 0; i < sizeof(test_images)/sizeof(test_images[0]); i++) {
        if (access(test_images[i], F_OK) != 0)
            continue;
        printf("\n--- Test Case: B-Tree COW Insertion & Search (%s) ---\n", test_images[i]);
        test_btree_cow_insert_and_search(test_images[i]);
        printf("PASS: B-Tree Copy-on-Write insertion and sorted traversal verified\n");
    }

    /* 16. Milestone 7: Filesystem File Creation & Extent Writes */
    for (size_t i = 0; i < sizeof(test_images)/sizeof(test_images[0]); i++) {
        if (access(test_images[i], F_OK) != 0)
            continue;
        printf("\n--- Test Case: File Creation & Extent Writes (%s) ---\n", test_images[i]);
        test_file_creation_and_extent_writes(test_images[i]);
        printf("PASS: File creation and extent allocation verified\n");
    }

    printf("\n=======================================================\n");
    printf("ALL APFS TESTS PASSED SUCCESSFULLY (100%%)\n");
    printf("=======================================================\n");
    return 0;
}

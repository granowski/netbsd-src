/*	$NetBSD$	*/

#ifndef _FS_APFS_APFS_H_
#define _FS_APFS_APFS_H_

#include <sys/param.h>
#include <sys/mount.h>
#include <sys/vnode.h>
#include <sys/uuid.h>
#include <miscfs/genfs/genfs_node.h>

/* APFS Primitive Types */
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

/* Object Header */
typedef struct obj_phys {
    uint8_t  o_cksum[MAX_CKSUM_SIZE];
    oid_t    o_oid;
    xid_t    o_xid;
    uint32_t o_type;
    uint32_t o_subtype;
} obj_phys_t;

/* Object Types */
#define OBJECT_TYPE_MASK            0x0000ffff
#define OBJECT_TYPE_FLAGS_MASK      0xffff0000

#define OBJ_CONTAINER_SUPERBLOCK    0x00000001
#define OBJ_BTREE                   0x00000002
#define OBJ_BTREE_NODE              0x00000003
#define OBJ_SPACEMAN                0x00000005
#define OBJ_OMAP                    0x0000000b
#define OBJ_CHECKPOINT_MAP          0x0000000c
#define OBJ_FS                      0x0000000d
#define OBJ_FSTREE                  0x0000000e
#define OBJ_STORAGE_MASK            0xc0000000
#define OBJ_EPHEMERAL                0x80000000
#define OBJ_PHYSICAL                 0x40000000

#define CHECKPOINT_MAP_LAST         0x00000001

/* Container Superblock */
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
    struct uuid     nx_uuid;
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
    struct uuid nx_fusion_uuid;
    prange_t   nx_keylocker;
    uint64_t   nx_ephemeral_info[NX_EPH_INFO_COUNT];
    oid_t      nx_test_oid;
    oid_t      nx_fusion_mt_oid;
    oid_t      nx_fusion_wbc_oid;
    prange_t   nx_fusion_wbc;
    uint64_t   nx_newest_mounted_version;
    prange_t   nx_mkb_locker;
} nx_superblock_t;

/* Volume Superblock */
#define APFS_MAGIC 0x42535041
#define APFS_FS_UNENCRYPTED 0x00000001
#define APFS_FS_ONEKEY 0x00000008
#define APFS_INCOMPAT_SEALED_VOLUME 0x00000020
#define APFS_SEAL_BROKEN 0x00000001

#define APFS_HASH_SHA256       0x00000001
#define APFS_HASH_SHA512_256   0x00000002
#define APFS_HASH_SHA384       0x00000003
#define APFS_HASH_SHA512       0x00000004
#define APFS_VOL_ROLE_SYSTEM   0x0001
#define INTEGRITY_META_VERSION_1 1
#define INTEGRITY_META_VERSION_2 2
#define OBJECT_TYPE_INTEGRITY_META 0x0000001e

typedef struct integrity_meta_phys {
    obj_phys_t im_o;
    uint32_t im_version;
    uint32_t im_flags;
    uint32_t im_hash_type;
    uint32_t im_root_hash_offset;
    xid_t im_broken_xid;
    uint64_t im_reserved[9];
} __attribute__((packed)) integrity_meta_phys_t;

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
    struct uuid apfs_vol_uuid;
    uint64_t   apfs_last_mod_time;
    uint64_t   apfs_fs_flags;
    struct apfs_modified_by {
        uint8_t id[APFS_MODIFIED_NAMELEN];
        uint64_t timestamp;
        xid_t last_xid;
    } apfs_formatted_by;
    struct apfs_modified_by apfs_modified_by[APFS_MAX_HIST];
    uint8_t    apfs_volname[APFS_VOLNAME_LEN];
    uint32_t   apfs_next_doc_id;
    uint16_t   apfs_role;
    uint16_t   apfs_reserved;
    xid_t      apfs_root_to_xid;
    oid_t      apfs_er_state_oid;
    uint64_t   apfs_cloneinfo_id_epoch;
    uint64_t   apfs_cloneinfo_xid;
    oid_t      apfs_snap_meta_ext_oid;
    struct uuid apfs_volume_group_id;
    oid_t      apfs_integrity_meta_oid;
    oid_t      apfs_fext_tree_oid;
    uint32_t   apfs_fext_tree_type;
    uint32_t   apfs_reserved_type;
    oid_t      apfs_reserved_oid;
} apfs_superblock_t;

/* Object Map */
typedef struct omap_phys {
    obj_phys_t omap_o;
    uint32_t   omap_flags;
    uint32_t   omap_snap_count;
    uint32_t   omap_tree_type;
    uint32_t   omap_snapshot_tree_type;
    oid_t      omap_tree_oid;
    oid_t      omap_snapshot_tree_oid;
    xid_t      omap_most_recent_snap_xid;
    xid_t      omap_pending_revert_xid;
} omap_phys_t;

typedef struct omap_key {
    oid_t ok_oid;
    xid_t ok_xid;
} omap_key_t;

typedef struct omap_val {
    uint32_t ov_flags;
    uint32_t ov_size;
    apfs_paddr_t  ov_paddr;
} omap_val_t;

#define OMAP_VAL_DELETED       0x00000001
#define OMAP_VAL_SAVED         0x00000002
#define OMAP_VAL_ENCRYPTED     0x00000004
#define OMAP_VAL_NOHEADER      0x00000008
#define OMAP_VAL_CRYPTO_GENERATION 0x00000010

/* Checkpoint Mapping */
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

/* Space Manager */
typedef struct spaceman_phys {
    obj_phys_t sm_o;
    uint32_t   sm_block_size;
    uint32_t   sm_pad;
    uint64_t   sm_block_count;
    uint32_t   sm_chunk_count;
    uint32_t   sm_cib_count;
    uint32_t   sm_cab_count;
    uint32_t   sm_free_count;
    oid_t      sm_idx_btree_oid;
    oid_t      sm_free_queue_oid;
} spaceman_phys_t;

typedef struct chunk_info_phys {
    uint64_t ci_addr;
    uint64_t ci_block_count;
    uint64_t ci_free_count;
    oid_t    ci_bitmap_oid;
} chunk_info_phys_t;

/* B-Tree structures */
typedef struct btree_node_phys {
    obj_phys_t btn_o;
    uint16_t   btn_flags;
    uint16_t   btn_level;
    uint32_t   btn_nkeys;
    uint16_t   btn_table_space_off;
    uint16_t   btn_table_space_len;
    uint16_t   btn_free_space_off;
    uint16_t   btn_free_space_len;
    uint16_t   btn_key_free_list_off;
    uint16_t   btn_key_free_list_len;
    uint16_t   btn_val_free_list_off;
    uint16_t   btn_val_free_list_len;
    /* ... table of contents and KV data follow ... */
} btree_node_phys_t;

#define BTNODE_ROOT           0x0001
#define BTNODE_LEAF           0x0002
#define BTNODE_FIXED_KV_SIZE  0x0004
#define BTREE_EPHEMERAL        0x00000008
#define BTREE_PHYSICAL         0x00000010
#define BTREE_KV_NONALIGNED    0x00000040
#define BTREE_HASHED           0x00000080
#define BTREE_NOHEADER         0x00000100
#define BTNODE_HASHED          0x0008
#define BTNODE_NOHEADER        0x0010

/* File-System Records */
#define APFS_TYPE_ANY       0x0
#define APFS_TYPE_INODE     0x3
#define APFS_TYPE_DIR_REC   0x9
#define APFS_TYPE_EXTENT    0x8

typedef struct j_key {
    uint64_t obj_id_and_type;
} j_key_t;

typedef struct j_extent_key {
    uint64_t obj_id_and_type;
    uint64_t logical_addr;
} j_extent_key_t;

#define OBJ_ID_MASK   0xfffffffffffffff0ULL
#define OBJ_TYPE_MASK 0x000000000000000fULL
#define OBJ_TYPE_SHIFT 0

typedef struct j_inode_val {
    uint64_t parent_id;
    uint64_t private_id;
    uint64_t create_time;
    uint64_t mod_time;
    uint64_t change_time;
    uint64_t access_time;
    uint64_t internal_flags;
    union {
        int32_t nchildren;
        int32_t nlink;
    };
    uint32_t default_protection_class;
    uint32_t write_generation_counter;
    uint32_t bsd_flags;
    uint32_t owner;
    uint32_t group;
    uint16_t mode;
    uint16_t pad1;
    uint64_t uncompressed_size;
    uint8_t xfields[0];
} __attribute__((packed)) j_inode_val_t;

/* Directory Entry Record Types */
#define DREC_TYPE_MASK      0x000f
#define DREC_TYPE_SHIFT     0
#define DREC_FLAGS_MASK     0xfff0

typedef struct j_drec_key {
    uint64_t obj_id_and_type;
    uint32_t name_len_and_hash;
    uint8_t  name[0];
} j_drec_key_t;

#define DREC_NLEN_MASK 0x000003ff
#define DREC_HASH_MASK 0xfffffc00
#define DREC_HASH_SHIFT 10

typedef struct j_drec_val {
    uint64_t file_id;
    uint64_t date_added;
    uint16_t flags;
    uint16_t xfields_len;
} j_drec_val_t;

/* Extent Records */
typedef struct j_phys_ext_key {
    uint64_t logical_addr;
} j_phys_ext_key_t;

typedef struct j_phys_ext_val {
    uint64_t len_and_flags;
    uint64_t phys_addr;
} j_phys_ext_val_t;

#define EXTENT_LEN_MASK 0x00ffffffffffffffULL
#define EXTENT_KIND_MASK 0xff00000000000000ULL

/* B-Tree Node Table of Contents Entry */
typedef struct btree_toc_entry {
    uint16_t key_off;
    uint16_t key_len;
    uint16_t val_off;
    uint16_t val_len;
} btree_toc_entry_t;

typedef struct btree_toc_fixed_entry {
    uint16_t key_off;
    uint16_t val_off;
} btree_toc_fixed_entry_t;

typedef struct btree_info {
    uint32_t bt_flags;
    uint32_t bt_node_size;
    uint32_t bt_key_size;
    uint32_t bt_val_size;
    uint32_t bt_longest_key;
    uint32_t bt_longest_val;
    uint64_t bt_key_count;
    uint64_t bt_node_count;
} btree_info_t;

typedef struct btree_index_node_val {
    oid_t child_oid;
    uint8_t child_hash[BTREE_NODE_HASH_SIZE_MAX];
} btree_index_node_val_t;

/* NetBSD Internal Structures */

struct apfs_args {
	char *fspec;		/* block special device to mount */
};

#ifdef _KERNEL
struct apfsmount {
    struct mount    *am_mountp;
    dev_t            am_dev;
    struct vnode    *am_devvp;
    uint32_t         am_block_size;
    uint32_t         am_block_shift;
    nx_superblock_t  am_nx;
    apfs_superblock_t am_sb;
    uint32_t         am_desc_blocks;
    uint64_t         am_checkpoint_xid;
    uint32_t         am_hash_type;
    uint32_t         am_hash_size;
    uint8_t          am_root_hash[BTREE_NODE_HASH_SIZE_MAX];
    bool             am_sealed;
    kmutex_t         am_lock;
    struct vnode    *am_rootvp;
};

struct apfsnode {
    struct genfs_node a_gnode;
    struct vnode     *a_vnode;
    struct apfsmount *a_amp;
    oid_t             a_oid;
    j_inode_val_t     a_ino;
    bool              a_dirty;
};

#define VTOA(vp) ((struct apfsnode *)(vp)->v_data)

/* VFS Operations */
VFS_PROTOS(apfs);

/* B-Tree Helpers */
typedef int (*apfs_btree_iter_cb)(void *, const void *, size_t, const void *, size_t);
int apfs_btree_search(struct apfsmount *, oid_t, oid_t, void *, size_t,
    void *, size_t, void *, size_t);
int apfs_btree_iterate(struct apfsmount *, oid_t, oid_t, void *, size_t, apfs_btree_iter_cb, void *);
int apfs_btree_insert(struct apfsmount *, oid_t *, void *, void *);
int apfs_btree_remove(struct apfsmount *, oid_t *, void *);
int apfs_bread(struct apfsmount *, apfs_paddr_t, struct buf **);
bool apfs_checksum_valid(struct apfsmount *, const void *);
int apfs_select_checkpoint(struct apfsmount *);
int apfs_checkpoint_lookup(struct apfsmount *, oid_t, oid_t,
    apfs_paddr_t *);

/* Space Manager Helpers */
int apfs_alloc_block(struct apfsmount *, apfs_paddr_t *);
int apfs_free_block(struct apfsmount *, apfs_paddr_t);

/* OMap Helpers */
int apfs_omap_lookup(struct apfsmount *, oid_t, oid_t, xid_t, apfs_paddr_t *);
int apfs_omap_update(struct apfsmount *, oid_t, xid_t, apfs_paddr_t);

/* Checksum */
uint64_t apfs_fletcher64(const void *, size_t);
int apfs_hash_data(struct apfsmount *, const void *, size_t,
    uint8_t[BTREE_NODE_HASH_SIZE_MAX]);

/* Vnode Operations */
extern int (**apfs_vnodeop_p)(void *);
extern const struct vnodeopv_desc * const apfs_vnodeopv_descs[];

int apfs_vop_lookup(void *);
int apfs_vop_create(void *);
int apfs_vop_mknod(void *);
int apfs_vop_open(void *);
int apfs_vop_close(void *);
int apfs_vop_access(void *);
int apfs_vop_getattr(void *);
int apfs_vop_setattr(void *);
int apfs_vop_read(void *);
int apfs_vop_write(void *);
int apfs_vop_fsync(void *);
int apfs_vop_remove(void *);
int apfs_vop_mkdir(void *);
int apfs_vop_rmdir(void *);
int apfs_vop_readdir(void *);
int apfs_vop_inactive(void *);
int apfs_vop_reclaim(void *);
int apfs_vop_strategy(void *);
int apfs_vop_bmap(void *);
#endif /* _KERNEL */

#endif /* _FS_APFS_APFS_H_ */

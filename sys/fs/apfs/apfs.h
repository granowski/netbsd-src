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

#define MAX_CKSUM_SIZE 8

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
#define OBJ_FS                      0x0000000d

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
} nx_superblock_t;

/* Volume Superblock */
#define APFS_MAGIC 0x42535041

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
    // ...
    oid_t      apfs_omap_oid;
    oid_t      apfs_root_tree_oid;
    uint64_t   apfs_next_obj_id;
    uint64_t   apfs_num_files;
    uint64_t   apfs_num_directories;
    // ...
} apfs_superblock_t;

/* Object Map */
typedef struct omap_phys {
    obj_phys_t omap_o;
    uint32_t   omap_flags;
    uint32_t   omap_snap_count;
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

/* Checkpoint Mapping */
typedef struct checkpoint_mapping {
    obj_phys_t cpm_o;
    uint32_t   cpm_type;
    uint32_t   cpm_subtype;
    uint32_t   cpm_size;
    uint32_t   cpm_pad;
    apfs_paddr_t    cpm_paddr;
} checkpoint_mapping_t;

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

/* File-System Records */
#define APFS_TYPE_ANY       0x0
#define APFS_TYPE_INODE     0x1
#define APFS_TYPE_DIR_REC   0x3
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
    uint32_t nchildren;
    uint32_t nlink;
    uint32_t bsd_flags;
    uint32_t owner;
    uint32_t group;
    uint16_t mode;
    uint16_t pad1;
    uint64_t uncompressed_size;
    /* ... additional fields ... */
    uint64_t cloned_inum;
    uint64_t purgeable_flags;
} j_inode_val_t;

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

/* Checkpoint Structures */
typedef struct checkpoint_desc_phys {
    obj_phys_t cpd_o;
    uint32_t   cpd_flags;
    uint32_t   cpd_count;
    checkpoint_mapping_t cpd_map[0];
} checkpoint_desc_phys_t;

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
int apfs_btree_search(struct apfsmount *, oid_t, void *, void *, void *);
int apfs_btree_iterate(struct apfsmount *, oid_t, void *, apfs_btree_iter_cb, void *);
int apfs_btree_insert(struct apfsmount *, oid_t *, void *, void *);
int apfs_btree_remove(struct apfsmount *, oid_t *, void *);

/* Space Manager Helpers */
int apfs_alloc_block(struct apfsmount *, apfs_paddr_t *);
int apfs_free_block(struct apfsmount *, apfs_paddr_t);

/* OMap Helpers */
int apfs_omap_lookup(struct apfsmount *, oid_t, xid_t, apfs_paddr_t *);
int apfs_omap_update(struct apfsmount *, oid_t, xid_t, apfs_paddr_t);

/* Checksum */
uint64_t apfs_fletcher64(const void *, size_t);

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

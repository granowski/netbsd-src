/*	$NetBSD$	*/

#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/disk.h>
#include <sys/endian.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/uuid.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define APFS_BLOCK_SIZE		4096
#define APFS_MIN_BLOCKS		256
#define APFS_BLOCKS_PER_CHUNK	32768
#define APFS_CHUNKS_PER_CIB	126
#define APFS_VOLNAME_LEN	256
#define APFS_MAX_HIST		8
#define APFS_DESC_BASE		1
#define APFS_DESC_BLOCKS	8
#define APFS_DATA_BASE		9
#define APFS_DATA_BLOCKS	8
#define APFS_SPACEMAN_BLOCK	17
#define APFS_CIB_BASE		18
#define APFS_XID			1
#define APFS_NEXT_XID		2
#define NX_INCOMPAT_VERSION1		0x0000000000000002ULL

#define OBJ_CONTAINER_SUPERBLOCK	0x00000001
#define OBJ_BTREE			0x00000002
#define OBJ_SPACEMAN			0x00000005
#define OBJ_SPACEMAN_CIB		0x00000007
#define OBJ_OMAP			0x0000000b
#define OBJ_CHECKPOINT_MAP		0x0000000c
#define OBJ_FS				0x0000000d
#define OBJ_FSTREE			0x0000000e
#define OBJ_EPHEMERAL			0x80000000
#define OBJ_PHYSICAL			0x40000000
#define CHECKPOINT_MAP_LAST		0x00000001
#define BTREE_PHYSICAL			0x00000010
#define BTREE_SEQUENTIAL_INSERT		0x00000002
#define BTNODE_ROOT			0x0001
#define BTNODE_LEAF			0x0002
#define BTNODE_FIXED_KV_SIZE		0x0004
#define APFS_MAGIC			0x42535041
#define NX_MAGIC			0x4253584e
#define APFS_FS_UNENCRYPTED		0x00000001
#define APFS_TYPE_INODE			0x3
#define APFS_ROOT_INO			2
#define APFS_KEY(oid, type)		(((uint64_t)(oid)) | \
					((uint64_t)(type) << 60))

typedef struct __attribute__((__packed__)) {
	uint8_t		cksum[8];
	uint64_t	oid;
	uint64_t	xid;
	uint32_t	type;
	uint32_t	subtype;
} obj_phys_t;

typedef struct __attribute__((__packed__)) {
	obj_phys_t	o;
	uint32_t	magic;
	uint32_t	block_size;
	uint64_t	block_count;
	uint64_t	features;
	uint64_t	readonly_compatible_features;
	uint64_t	incompatible_features;
	uint8_t		uuid[16];
	uint64_t	next_oid;
	uint64_t	next_xid;
	uint32_t	xp_desc_blocks;
	uint32_t	xp_data_blocks;
	int64_t		xp_desc_base;
	int64_t		xp_data_base;
	uint32_t	xp_desc_next;
	uint32_t	xp_data_next;
	uint32_t	xp_desc_index;
	uint32_t	xp_desc_len;
	uint32_t	xp_data_index;
	uint32_t	xp_data_len;
	uint64_t	spaceman_oid;
	uint64_t	omap_oid;
	uint64_t	reaper_oid;
	uint32_t	test_type;
	uint32_t	max_file_systems;
	uint64_t	fs_oid[100];
} nx_superblock_t;

typedef struct __attribute__((__packed__)) {
	obj_phys_t	o;
	uint32_t	magic;
	uint32_t	fs_index;
	uint64_t	features;
	uint64_t	readonly_compatible_features;
	uint64_t	incompatible_features;
	uint64_t	unmount_time;
	uint64_t	fs_reserve_block_count;
	uint64_t	fs_quota_block_count;
	uint64_t	fs_alloc_count;
	uint8_t		meta_crypto[20];
	uint32_t	root_tree_type;
	uint32_t	extentref_tree_type;
	uint32_t	snap_meta_tree_type;
	uint64_t	omap_oid;
	uint64_t	root_tree_oid;
	uint64_t	extentref_tree_oid;
	uint64_t	snap_meta_tree_oid;
	uint64_t	revert_to_xid;
	uint64_t	revert_to_sblock_oid;
	uint64_t	next_obj_id;
	uint64_t	num_files;
	uint64_t	num_directories;
	uint64_t	num_symlinks;
	uint64_t	num_other_fsobjects;
	uint64_t	num_snapshots;
	uint64_t	total_blocks_alloced;
	uint64_t	total_blocks_freed;
	uint8_t		vol_uuid[16];
	uint64_t	last_mod_time;
	uint64_t	fs_flags;
	uint8_t		formatted_by[48];
	uint8_t		modified_by[APFS_MAX_HIST * 48];
	uint8_t		volname[APFS_VOLNAME_LEN];
} apfs_superblock_t;

typedef struct __attribute__((__packed__)) {
	obj_phys_t	o;
	uint32_t	flags;
	uint32_t	snap_count;
	uint32_t	tree_type;
	uint32_t	snapshot_tree_type;
	uint64_t	tree_oid;
	uint64_t	snapshot_tree_oid;
	uint64_t	most_recent_snap_xid;
	uint64_t	pending_revert_xid;
} omap_phys_t;

typedef struct __attribute__((__packed__)) {
	uint64_t	oid;
	uint64_t	xid;
} omap_key_t;

typedef struct __attribute__((__packed__)) {
	uint32_t	flags;
	uint32_t	size;
	int64_t		paddr;
} omap_val_t;

typedef struct __attribute__((__packed__)) {
	uint32_t	type;
	uint32_t	subtype;
	uint32_t	size;
	uint32_t	pad;
	uint64_t	fs_oid;
	uint64_t	oid;
	int64_t		paddr;
} checkpoint_mapping_t;

typedef struct __attribute__((__packed__)) {
	obj_phys_t	o;
	uint32_t	flags;
	uint32_t	count;
	checkpoint_mapping_t	mapping[1];
} checkpoint_map_phys_t;

typedef struct __attribute__((__packed__)) {
	uint64_t	block_count;
	uint64_t	chunk_count;
	uint32_t	cib_count;
	uint32_t	cab_count;
	uint64_t	free_count;
	uint32_t	addr_offset;
	uint32_t	reserved;
	uint64_t	reserved2;
} spaceman_device_t;

typedef struct __attribute__((__packed__)) {
	obj_phys_t	o;
	uint32_t	block_size;
	uint32_t	blocks_per_chunk;
	uint32_t	chunks_per_cib;
	uint32_t	cibs_per_cab;
	spaceman_device_t	dev[2];
	uint32_t	flags;
	uint32_t	ip_bm_tx_multiplier;
	uint64_t	ip_block_count;
	uint32_t	ip_bm_size_in_blocks;
	uint32_t	ip_bm_block_count;
	int64_t		ip_bm_base;
	int64_t		ip_base;
	uint64_t	fs_reserve_block_count;
	uint64_t	fs_reserve_alloc_count;
	uint8_t		free_queues[3 * 40];
	uint16_t	ip_bm_free_head;
	uint16_t	ip_bm_free_tail;
	uint32_t	ip_bm_xid_offset;
	uint32_t	ip_bitmap_offset;
	uint32_t	ip_bm_free_next_offset;
	uint32_t	version;
	uint32_t	struct_size;
} spaceman_phys_t;

typedef struct __attribute__((__packed__)) {
	uint64_t	xid;
	uint64_t	addr;
	uint32_t	block_count;
	uint32_t	free_count;
	int64_t		bitmap_addr;
} chunk_info_phys_t;

typedef struct __attribute__((__packed__)) {
	obj_phys_t	o;
	uint32_t	index;
	uint32_t	chunk_info_count;
	chunk_info_phys_t	chunk_info[APFS_CHUNKS_PER_CIB];
} chunk_info_block_phys_t;

typedef struct __attribute__((__packed__)) {
	obj_phys_t	o;
	uint16_t	flags;
	uint16_t	level;
	uint32_t	nkeys;
	uint16_t	table_space_off;
	uint16_t	table_space_len;
	uint16_t	free_space_off;
	uint16_t	free_space_len;
	uint16_t	key_free_list_off;
	uint16_t	key_free_list_len;
	uint16_t	val_free_list_off;
	uint16_t	val_free_list_len;
} btree_node_phys_t;

typedef struct __attribute__((__packed__)) {
	uint16_t	key_off;
	uint16_t	key_len;
	uint16_t	val_off;
	uint16_t	val_len;
} btree_toc_entry_t;

typedef struct __attribute__((__packed__)) {
	uint16_t	key_off;
	uint16_t	val_off;
} btree_toc_fixed_entry_t;

typedef struct __attribute__((__packed__)) {
	uint32_t	flags;
	uint32_t	node_size;
	uint32_t	key_size;
	uint32_t	val_size;
	uint32_t	longest_key;
	uint32_t	longest_val;
	uint64_t	key_count;
	uint64_t	node_count;
} btree_info_t;

typedef struct __attribute__((__packed__)) {
	uint64_t	parent_id;
	uint64_t	private_id;
	uint64_t	create_time;
	uint64_t	mod_time;
	uint64_t	change_time;
	uint64_t	access_time;
	uint64_t	internal_flags;
	int32_t		nchildren;
	uint32_t	default_protection_class;
	uint32_t	write_generation_counter;
	uint32_t	bsd_flags;
	uint32_t	owner;
	uint32_t	group;
	uint16_t	mode;
	uint16_t	pad;
	uint64_t	uncompressed_size;
} j_inode_val_t;

_Static_assert(sizeof(obj_phys_t) == 32, "APFS object header size");
_Static_assert(sizeof(nx_superblock_t) == 984, "NX superblock prefix size");
_Static_assert(sizeof(struct uuid) == 16, "APFS UUID size");
_Static_assert(offsetof(apfs_superblock_t, volname) == 704,
    "volume name offset");
_Static_assert(sizeof(spaceman_phys_t) == 344, "Space Manager size");
_Static_assert(sizeof(chunk_info_block_phys_t) <= APFS_BLOCK_SIZE,
    "CIB must fit in one APFS block");
_Static_assert(sizeof(j_inode_val_t) == 92, "root inode value size");

static void usage(void) __dead;

static uint64_t
apfs_checksum(const void *block)
{
	const uint32_t *words = block;
	uint64_t sum1 = 0, sum2 = 0;
	uint32_t c1, c2;

	for (size_t i = 2; i < APFS_BLOCK_SIZE / sizeof(*words); i++) {
		sum1 += le32toh(words[i]);
		sum2 += sum1;
	}
	c1 = UINT32_MAX - (uint32_t)((sum1 + sum2) % UINT32_MAX);
	c2 = UINT32_MAX - (uint32_t)((sum1 + c1) % UINT32_MAX);
	return ((uint64_t)c2 << 32) | c1;
}

static void
apfs_set_checksum(void *block)
{
	obj_phys_t *o = block;
	uint64_t checksum = htole64(apfs_checksum(block));

	memcpy(o->cksum, &checksum, sizeof(checksum));
}

static int
write_block(int fd, uint64_t block_number, const void *buf)
{
	const uint8_t *p = buf;
	off_t offset = (off_t)(block_number * APFS_BLOCK_SIZE);
	size_t remaining = APFS_BLOCK_SIZE;

	while (remaining != 0) {
		ssize_t n = pwrite(fd, p, remaining, offset);
		if (n == -1) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0) {
			errno = EIO;
			return -1;
		}
		p += n;
		offset += n;
		remaining -= (size_t)n;
	}
	return 0;
}

static int
get_media_size(int fd, const struct stat *st, uint64_t *sizep)
{
	off_t media_size;

	if (S_ISREG(st->st_mode)) {
		if (st->st_size < 0)
			return -1;
		*sizep = (uint64_t)st->st_size;
		return 0;
	}
	if (!S_ISBLK(st->st_mode) && !S_ISCHR(st->st_mode)) {
		errno = ENODEV;
		return -1;
	}
	if (ioctl(fd, DIOCGMEDIASIZE, &media_size) == -1)
		return -1;
	if (media_size <= 0) {
		errno = EINVAL;
		return -1;
	}
	*sizep = (uint64_t)media_size;
	return 0;
}

static void
write_tree_node(uint8_t *block, uint64_t oid, uint32_t subtype,
    const void *key, uint16_t key_len, const void *val, uint16_t val_len,
    uint32_t nkeys, bool fixed_kv)
{
	btree_node_phys_t *node = (btree_node_phys_t *)block;
	btree_toc_entry_t *toc;
	btree_toc_fixed_entry_t *fixed_toc;
	btree_info_t *info;
	size_t toc_size = fixed_kv ? sizeof(*fixed_toc) : sizeof(*toc);
	size_t table_len = nkeys * toc_size;
	size_t data_end = APFS_BLOCK_SIZE - sizeof(*info);
	size_t key_area = sizeof(*node) + table_len;
	size_t keys_len = (size_t)nkeys * key_len;
	size_t vals_len = (size_t)nkeys * val_len;

	memset(block, 0, APFS_BLOCK_SIZE);
	node->o.oid = htole64(oid);
	node->o.xid = htole64(APFS_XID);
	node->o.type = htole32(OBJ_BTREE | OBJ_PHYSICAL);
	node->o.subtype = htole32(subtype);
	node->flags = htole16(BTNODE_ROOT | BTNODE_LEAF |
	    (fixed_kv ? BTNODE_FIXED_KV_SIZE : 0));
	node->level = htole16(0);
	node->nkeys = htole32(nkeys);
	node->table_space_off = htole16(0);
	node->table_space_len = htole16(table_len);
	for (uint32_t i = 0; i < nkeys; i++) {
		uint16_t key_off = i * key_len;
		uint16_t val_off = (i + 1) * val_len;

		if (fixed_kv) {
			fixed_toc = (btree_toc_fixed_entry_t *)(block +
			    sizeof(*node) + i * toc_size);
			fixed_toc->key_off = htole16(key_off);
			fixed_toc->val_off = htole16(val_off);
		} else {
			toc = (btree_toc_entry_t *)(block + sizeof(*node) +
			    i * toc_size);
			toc->key_off = htole16(key_off);
			toc->key_len = htole16(key_len);
			toc->val_off = htole16(val_off);
			toc->val_len = htole16(val_len);
		}
		memcpy(block + key_area + (size_t)i * key_len,
		    (const uint8_t *)key + (size_t)i * key_len, key_len);
		memcpy(block + data_end - val_off,
		    (const uint8_t *)val + (size_t)i * val_len, val_len);
	}
	if (nkeys == 0 || key_area > data_end ||
	    keys_len > data_end - key_area || vals_len > data_end ||
	    vals_len > data_end - key_area - keys_len)
		errx(EXIT_FAILURE, "initial B-tree node does not fit");

	info = (btree_info_t *)(block + data_end);
	info->flags = htole32(BTREE_PHYSICAL | BTREE_SEQUENTIAL_INSERT);
	info->node_size = htole32(APFS_BLOCK_SIZE);
	info->key_size = htole32(key_len);
	info->val_size = htole32(val_len);
	info->longest_key = htole32(key_len);
	info->longest_val = htole32(val_len);
	info->key_count = htole64(nkeys);
	info->node_count = htole64(1);
	apfs_set_checksum(block);
}

static int
format_apfs(int fd, uint64_t block_count, const char *volname)
{
	uint8_t block[APFS_BLOCK_SIZE], bitmap[APFS_BLOCK_SIZE];
	struct uuid container_uuid, volume_uuid;
	nx_superblock_t *nx;
	apfs_superblock_t *vsb;
	spaceman_phys_t *sm;
	chunk_info_block_phys_t *cib;
	checkpoint_map_phys_t *cpm;
	uint64_t chunk_count, cib_count, bitmap_paddr, container_omap_paddr;
	uint64_t container_tree_paddr, volume_sb_paddr, volume_omap_paddr;
	uint64_t volume_tree_paddr, fs_tree_paddr, next_paddr;
	uint64_t volume_oid, root_tree_oid;
	size_t name_len = strlen(volname);

	if (name_len == 0 || name_len >= APFS_VOLNAME_LEN) {
		warnx("volume name must contain 1 to %d bytes",
		    APFS_VOLNAME_LEN - 1);
		return -1;
	}
	if (block_count < APFS_MIN_BLOCKS) {
		warnx("target is too small: need at least %u APFS blocks",
		    APFS_MIN_BLOCKS);
		return -1;
	}
	if (block_count > INT64_MAX / APFS_BLOCK_SIZE) {
		warnx("target is too large");
		return -1;
	}

	chunk_count = block_count / APFS_BLOCKS_PER_CHUNK +
	    (block_count % APFS_BLOCKS_PER_CHUNK != 0);
	cib_count = chunk_count / APFS_CHUNKS_PER_CIB +
	    (chunk_count % APFS_CHUNKS_PER_CIB != 0);
	if (cib_count > (APFS_BLOCK_SIZE - sizeof(spaceman_phys_t)) /
	    sizeof(uint64_t)) {
		warnx("target is too large for this formatter's Space Manager");
		return -1;
	}

	bitmap_paddr = APFS_CIB_BASE + cib_count;
	container_omap_paddr = bitmap_paddr + 1;
	container_tree_paddr = container_omap_paddr + 1;
	volume_sb_paddr = container_tree_paddr + 1;
	volume_omap_paddr = volume_sb_paddr + 1;
	volume_tree_paddr = volume_omap_paddr + 1;
	fs_tree_paddr = volume_tree_paddr + 1;
	next_paddr = fs_tree_paddr + 1;
	if (next_paddr >= APFS_BLOCKS_PER_CHUNK ||
	    next_paddr >= block_count) {
		warnx("target is too small for initial APFS metadata");
		return -1;
	}
	if (uuidgen(&container_uuid, 1) == -1 ||
	    uuidgen(&volume_uuid, 1) == -1) {
		warn("uuidgen");
		return -1;
	}

	memset(block, 0, sizeof(block));
	if (write_block(fd, 0, block) == -1 || fsync(fd) == -1) {
		warn("cannot invalidate old container superblock");
		return -1;
	}

	for (uint64_t paddr = APFS_DESC_BASE; paddr <
	    APFS_DATA_BASE + APFS_DATA_BLOCKS; paddr++) {
		if (paddr == APFS_DESC_BASE || paddr == APFS_DESC_BASE + 1)
			continue;
		if (write_block(fd, paddr, block) == -1) {
			warn("cannot clear checkpoint ring block %llu",
			    (unsigned long long)paddr);
			return -1;
		}
	}

	memset(block, 0, sizeof(block));
	sm = (spaceman_phys_t *)block;
	sm->o.oid = htole64(APFS_SPACEMAN_BLOCK);
	sm->o.xid = htole64(APFS_XID);
	sm->o.type = htole32(OBJ_SPACEMAN | OBJ_EPHEMERAL);
	sm->block_size = htole32(APFS_BLOCK_SIZE);
	sm->blocks_per_chunk = htole32(APFS_BLOCKS_PER_CHUNK);
	sm->chunks_per_cib = htole32(APFS_CHUNKS_PER_CIB);
	sm->dev[0].block_count = htole64(block_count);
	sm->dev[0].chunk_count = htole64(chunk_count);
	sm->dev[0].cib_count = htole32(cib_count);
	sm->dev[0].free_count = htole64(block_count - next_paddr -
	    (chunk_count - 1));
	sm->dev[0].addr_offset = htole32(sizeof(*sm));
	sm->version = htole32(1);
	sm->struct_size = htole32(sizeof(*sm));
	for (uint64_t i = 0; i < cib_count; i++) {
		uint64_t cib_paddr = APFS_CIB_BASE + i;
		uint64_t cib_paddr_le = htole64(cib_paddr);
		memcpy(block + sizeof(*sm) + i * sizeof(cib_paddr_le),
		    &cib_paddr_le, sizeof(cib_paddr_le));
	}
	apfs_set_checksum(block);
	if (write_block(fd, APFS_SPACEMAN_BLOCK, block) == -1) {
		warn("cannot write Space Manager");
		return -1;
	}

	for (uint64_t i = 0; i < cib_count; i++) {
		uint64_t first_chunk = i * APFS_CHUNKS_PER_CIB;
		uint32_t count = (uint32_t)MIN((uint64_t)APFS_CHUNKS_PER_CIB,
		    chunk_count - first_chunk);
		uint64_t cib_paddr = APFS_CIB_BASE + i;

		memset(block, 0, sizeof(block));
		cib = (chunk_info_block_phys_t *)block;
		cib->o.oid = htole64(cib_paddr);
		cib->o.xid = htole64(APFS_XID);
		cib->o.type = htole32(OBJ_SPACEMAN_CIB | OBJ_EPHEMERAL);
		cib->index = htole32(i);
		cib->chunk_info_count = htole32(count);
		for (uint32_t j = 0; j < count; j++) {
			uint64_t chunk_index = first_chunk + j;
			uint64_t chunk_start = chunk_index * APFS_BLOCKS_PER_CHUNK;
			uint32_t chunk_blocks = (uint32_t)MIN(
			    block_count - chunk_start,
			    (uint64_t)APFS_BLOCKS_PER_CHUNK);
			chunk_info_phys_t *ci = &cib->chunk_info[j];

			ci->xid = htole64(APFS_XID);
			ci->addr = htole64(chunk_start);
			ci->block_count = htole32(chunk_blocks);
			ci->free_count = htole32(chunk_blocks -
			    (chunk_index == 0 ? (uint32_t)next_paddr : 1));
			ci->bitmap_addr = (int64_t)htole64(chunk_index == 0 ?
			    bitmap_paddr : chunk_start);
		}
		apfs_set_checksum(block);
		if (write_block(fd, cib_paddr, block) == -1) {
			warn("cannot write Space Manager CIB %llu",
			    (unsigned long long)i);
			return -1;
		}
	}

	memset(bitmap, 0, sizeof(bitmap));
	for (uint64_t i = 0; i < next_paddr; i++)
		bitmap[i >> 3] |= (uint8_t)(1U << (i & 7));
	if (write_block(fd, bitmap_paddr, bitmap) == -1) {
		warn("cannot write Space Manager bitmap");
		return -1;
	}
	for (uint64_t i = 1; i < chunk_count; i++) {
		uint64_t chunk_start = i * APFS_BLOCKS_PER_CHUNK;

		memset(bitmap, 0, sizeof(bitmap));
		bitmap[0] = 1;
		if (write_block(fd, chunk_start, bitmap) == -1) {
			warn("cannot write Space Manager bitmap for chunk %llu",
			    (unsigned long long)i);
			return -1;
		}
	}

	memset(block, 0, sizeof(block));
	omap_phys_t *omap = (omap_phys_t *)block;
	omap->o.oid = htole64(container_omap_paddr);
	omap->o.xid = htole64(APFS_XID);
	omap->o.type = htole32(OBJ_OMAP | OBJ_PHYSICAL);
	omap->flags = htole32(1);
	omap->tree_type = htole32(OBJ_BTREE | OBJ_PHYSICAL);
	omap->tree_oid = htole64(container_tree_paddr);
	apfs_set_checksum(block);
	if (write_block(fd, container_omap_paddr, block) == -1) {
		warn("cannot write container OMap");
		return -1;
	}

	volume_oid = volume_sb_paddr;
	root_tree_oid = fs_tree_paddr;
	omap_key_t container_keys[2] = {
		{ .oid = htole64(volume_oid), .xid = htole64(APFS_XID) },
		{ .oid = htole64(volume_omap_paddr),
		  .xid = htole64(APFS_XID) },
	};
	omap_val_t container_vals[2] = {
		{ .flags = htole32(0), .size = htole32(APFS_BLOCK_SIZE),
		  .paddr = (int64_t)htole64(volume_sb_paddr) },
		{ .flags = htole32(0), .size = htole32(APFS_BLOCK_SIZE),
		  .paddr = (int64_t)htole64(volume_omap_paddr) },
	};
	write_tree_node(block, container_tree_paddr, OBJ_OMAP,
	    container_keys, sizeof(container_keys[0]), container_vals,
	    sizeof(container_vals[0]), 2, true);
	if (write_block(fd, container_tree_paddr, block) == -1) {
		warn("cannot write container OMap tree");
		return -1;
	}

	memset(block, 0, sizeof(block));
	vsb = (apfs_superblock_t *)block;
	vsb->o.oid = htole64(volume_oid);
	vsb->o.xid = htole64(APFS_XID);
	vsb->o.type = htole32(OBJ_FS | OBJ_EPHEMERAL);
	vsb->magic = htole32(APFS_MAGIC);
	vsb->fs_index = htole32(0);
	vsb->root_tree_type = htole32(OBJ_BTREE);
	vsb->omap_oid = htole64(volume_omap_paddr);
	vsb->root_tree_oid = htole64(root_tree_oid);
	vsb->next_obj_id = htole64(next_paddr);
	vsb->num_directories = htole64(1);
	memcpy(vsb->vol_uuid, &volume_uuid, sizeof(vsb->vol_uuid));
	vsb->fs_flags = htole64(APFS_FS_UNENCRYPTED);
	memcpy(vsb->volname, volname, name_len);
	apfs_set_checksum(block);
	if (write_block(fd, volume_sb_paddr, block) == -1) {
		warn("cannot write volume superblock");
		return -1;
	}

	memset(block, 0, sizeof(block));
	omap = (omap_phys_t *)block;
	omap->o.oid = htole64(volume_omap_paddr);
	omap->o.xid = htole64(APFS_XID);
	omap->o.type = htole32(OBJ_OMAP | OBJ_PHYSICAL);
	omap->flags = htole32(1);
	omap->tree_type = htole32(OBJ_BTREE | OBJ_PHYSICAL);
	omap->tree_oid = htole64(volume_tree_paddr);
	apfs_set_checksum(block);
	if (write_block(fd, volume_omap_paddr, block) == -1) {
		warn("cannot write volume OMap");
		return -1;
	}

	omap_key_t omap_key = {
		.oid = htole64(root_tree_oid),
		.xid = htole64(APFS_XID),
	};
	omap_val_t omap_val = {
		.flags = htole32(0),
		.size = htole32(APFS_BLOCK_SIZE),
		.paddr = (int64_t)htole64(fs_tree_paddr),
	};
	write_tree_node(block, volume_tree_paddr, OBJ_OMAP,
	    &omap_key, sizeof(omap_key), &omap_val, sizeof(omap_val), 1, true);
	if (write_block(fd, volume_tree_paddr, block) == -1) {
		warn("cannot write volume OMap tree");
		return -1;
	}

	j_inode_val_t inode;
	memset(&inode, 0, sizeof(inode));
	inode.parent_id = htole64(APFS_ROOT_INO);
	inode.mode = htole16(S_IFDIR | 0755);
	uint64_t inode_key = htole64(APFS_KEY(APFS_ROOT_INO, APFS_TYPE_INODE));
	write_tree_node(block, root_tree_oid, OBJ_FSTREE,
	    &inode_key, sizeof(inode_key), &inode, sizeof(inode), 1, false);
	if (write_block(fd, fs_tree_paddr, block) == -1) {
		warn("cannot write initial filesystem tree");
		return -1;
	}

	memset(block, 0, sizeof(block));
	cpm = (checkpoint_map_phys_t *)block;
	cpm->o.oid = htole64(APFS_DESC_BASE);
	cpm->o.xid = htole64(APFS_XID);
	cpm->o.type = htole32(OBJ_CHECKPOINT_MAP | OBJ_PHYSICAL);
	cpm->flags = htole32(CHECKPOINT_MAP_LAST);
	cpm->count = htole32(1);
	cpm->mapping[0].type = htole32(OBJ_SPACEMAN | OBJ_EPHEMERAL);
	cpm->mapping[0].size = htole32(APFS_BLOCK_SIZE);
	cpm->mapping[0].oid = htole64(APFS_SPACEMAN_BLOCK);
	cpm->mapping[0].paddr = (int64_t)htole64(APFS_SPACEMAN_BLOCK);
	apfs_set_checksum(block);
	if (write_block(fd, APFS_DESC_BASE, block) == -1) {
		warn("cannot write checkpoint map");
		return -1;
	}

	memset(block, 0, sizeof(block));
	nx = (nx_superblock_t *)block;
	nx->o.oid = htole64(1);
	nx->o.xid = htole64(APFS_XID);
	nx->o.type = htole32(OBJ_CONTAINER_SUPERBLOCK | OBJ_EPHEMERAL);
	nx->magic = htole32(NX_MAGIC);
	nx->block_size = htole32(APFS_BLOCK_SIZE);
	nx->block_count = htole64(block_count);
	nx->incompatible_features = htole64(NX_INCOMPAT_VERSION1);
	memcpy(nx->uuid, &container_uuid, sizeof(nx->uuid));
	nx->next_oid = htole64(next_paddr);
	nx->next_xid = htole64(APFS_NEXT_XID);
	nx->xp_desc_blocks = htole32(APFS_DESC_BLOCKS);
	nx->xp_data_blocks = htole32(APFS_DATA_BLOCKS);
	nx->xp_desc_base = (int64_t)htole64(APFS_DESC_BASE);
	nx->xp_data_base = (int64_t)htole64(APFS_DATA_BASE);
	nx->xp_desc_next = htole32(2);
	nx->xp_data_next = htole32(0);
	nx->xp_desc_index = htole32(0);
	nx->xp_desc_len = htole32(2);
	nx->xp_data_index = htole32(0);
	nx->xp_data_len = htole32(0);
	nx->spaceman_oid = htole64(APFS_SPACEMAN_BLOCK);
	nx->omap_oid = htole64(container_omap_paddr);
	nx->max_file_systems = htole32(1);
	nx->fs_oid[0] = htole64(volume_oid);
	apfs_set_checksum(block);
	if (write_block(fd, APFS_DESC_BASE + 1, block) == -1 ||
	    fsync(fd) == -1) {
		warn("cannot write initial checkpoint");
		return -1;
	}
	if (write_block(fd, 0, block) == -1 || fsync(fd) == -1) {
		warn("cannot activate initial checkpoint");
		return -1;
	}

	return 0;
}

int
main(int argc, char *argv[])
{
	struct stat st;
	uint64_t media_size, block_count;
	const char *volname = "Untitled";
	int ch, fd, rv;

	while ((ch = getopt(argc, argv, "v:")) != -1) {
		switch (ch) {
		case 'v':
			volname = optarg;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 1)
		usage();

	fd = open(argv[0], O_RDWR);
	if (fd == -1)
		err(EXIT_FAILURE, "cannot open %s", argv[0]);
	if (fstat(fd, &st) == -1)
		err(EXIT_FAILURE, "cannot stat %s", argv[0]);
	if (get_media_size(fd, &st, &media_size) == -1)
		err(EXIT_FAILURE, "cannot determine media size of %s", argv[0]);
	if (media_size % APFS_BLOCK_SIZE != 0) {
		warnx("target size must be a multiple of %u bytes",
		    APFS_BLOCK_SIZE);
		(void)close(fd);
		return EXIT_FAILURE;
	}
	block_count = media_size / APFS_BLOCK_SIZE;
	rv = format_apfs(fd, block_count, volname);
	if (close(fd) == -1 && rv == 0)
		err(EXIT_FAILURE, "cannot close %s", argv[0]);
	if (rv == 0)
		printf("Created APFS container with volume \"%s\" on %s "
		    "(%llu blocks, %u-byte blocks)\n", volname, argv[0],
		    (unsigned long long)block_count, APFS_BLOCK_SIZE);
	return rv == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

static void
usage(void)
{
	fprintf(stderr, "usage: %s [-v volume_name] device\n", getprogname());
	exit(EXIT_FAILURE);
}

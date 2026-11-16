/*	$NetBSD$	*/
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/endian.h>
#include <sys/buf.h>
#include <sys/kmem.h>
#include <sys/sha2.h>
#include <sys/dirent.h>
#include <fs/apfs/apfs.h>
#include <fs/apfs/apfs_unicode.h>

int
apfs_hash_data(struct apfsmount *amp, const void *data, size_t len,
    uint8_t digest[BTREE_NODE_HASH_SIZE_MAX])
{
	uint8_t full_digest[SHA512_DIGEST_LENGTH];
	SHA256_CTX sha256;
	SHA384_CTX sha384;
	SHA512_CTX sha512;

	memset(digest, 0, BTREE_NODE_HASH_SIZE_MAX);
	switch (amp->am_hash_type) {
	case APFS_HASH_SHA256:
		SHA256_Init(&sha256);
		SHA256_Update(&sha256, data, len);
		SHA256_Final(digest, &sha256);
		explicit_memset(&sha256, 0, sizeof(sha256));
		return 0;
	case APFS_HASH_SHA512_256:
		/* SHA-512/256 uses the SHA-512 compression function with its own IV. */
		SHA512_Init(&sha512);
		sha512.state[0] = UINT64_C(0x22312194fc2bf72c);
		sha512.state[1] = UINT64_C(0x9f555fa3c84c64c2);
		sha512.state[2] = UINT64_C(0x2393b86b6f53b151);
		sha512.state[3] = UINT64_C(0x963877195940eabd);
		sha512.state[4] = UINT64_C(0x96283ee2a88effe3);
		sha512.state[5] = UINT64_C(0xbe5e1e2553863992);
		sha512.state[6] = UINT64_C(0x2b0199fc2c85b8aa);
		sha512.state[7] = UINT64_C(0x0eb72ddc81c52ca2);
		SHA512_Update(&sha512, data, len);
		SHA512_Final(full_digest, &sha512);
		memcpy(digest, full_digest, SHA256_DIGEST_LENGTH);
		explicit_memset(&sha512, 0, sizeof(sha512));
		explicit_memset(full_digest, 0, sizeof(full_digest));
		return 0;
	case APFS_HASH_SHA384:
		SHA384_Init(&sha384);
		SHA384_Update(&sha384, data, len);
		SHA384_Final(digest, &sha384);
		explicit_memset(&sha384, 0, sizeof(sha384));
		return 0;
	case APFS_HASH_SHA512:
		SHA512_Init(&sha512);
		SHA512_Update(&sha512, data, len);
		SHA512_Final(digest, &sha512);
		explicit_memset(&sha512, 0, sizeof(sha512));
		return 0;
	default:
		explicit_memset(full_digest, 0, sizeof(full_digest));
		return EOPNOTSUPP;
	}
}

/* Fletcher 64 checksum implementation for APFS */
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

    /* APFS stores the complemented Fletcher residues, not the raw sums. */
    c1 = UINT32_MAX - ((sum1 + sum2) % UINT32_MAX);
    c2 = UINT32_MAX - ((sum1 + c1) % UINT32_MAX);

    return (c2 << 32) | c1;
}

int
apfs_bread(struct apfsmount *amp, apfs_paddr_t paddr, struct buf **bpp)
{
	uint64_t sectors_per_block, blkno;

	if (paddr < 0 || amp->am_block_size < DEV_BSIZE ||
	    amp->am_block_size % DEV_BSIZE != 0)
		return EINVAL;

	sectors_per_block = amp->am_block_size / DEV_BSIZE;
	if ((uint64_t)paddr > (uint64_t)INT64_MAX / sectors_per_block)
		return EOVERFLOW;
	blkno = (uint64_t)paddr * sectors_per_block;

	return bread(amp->am_devvp, (daddr_t)blkno, amp->am_block_size, 0, bpp);
}

int
apfs_getblk(struct apfsmount *amp, apfs_paddr_t paddr, struct buf **bpp)
{
	uint64_t sectors_per_block, blkno;
	struct buf *bp;

	if (paddr < 0 || amp == NULL || amp->am_block_size < DEV_BSIZE ||
	    amp->am_block_size % DEV_BSIZE != 0 || bpp == NULL)
		return EINVAL;

	sectors_per_block = amp->am_block_size / DEV_BSIZE;
	if ((uint64_t)paddr > (uint64_t)INT64_MAX / sectors_per_block)
		return EOVERFLOW;
	blkno = (uint64_t)paddr * sectors_per_block;

	bp = getblk(amp->am_devvp, (daddr_t)blkno, amp->am_block_size, 0, 0);
	if (bp == NULL)
		return ENOMEM;

	*bpp = bp;
	return 0;
}

int
apfs_bwrite(struct apfsmount *amp, apfs_paddr_t paddr, struct buf *bp)
{
	uint64_t sectors_per_block, blkno;

	if (paddr < 0 || amp == NULL || amp->am_block_size < DEV_BSIZE ||
	    amp->am_block_size % DEV_BSIZE != 0 || bp == NULL)
		return EINVAL;

	sectors_per_block = amp->am_block_size / DEV_BSIZE;
	if ((uint64_t)paddr > (uint64_t)INT64_MAX / sectors_per_block)
		return EOVERFLOW;
	blkno = (uint64_t)paddr * sectors_per_block;

	bp->b_blkno = (daddr_t)blkno;
	bp->b_bcount = amp->am_block_size;
	return bwrite(bp);
}

int
apfs_bwrite_cow(apfs_tx_t *tx, apfs_paddr_t paddr, struct buf *bp)
{
	if (tx == NULL || tx->tx_amp == NULL || tx->tx_state != APFS_TX_STATE_ACTIVE)
		return EINVAL;

	return apfs_bwrite(tx->tx_amp, paddr, bp);
}

void
apfs_obj_init(void *object, oid_t oid, uint64_t xid, uint32_t type,
    uint32_t subtype)
{
	obj_phys_t *obj = (obj_phys_t *)object;

	if (obj == NULL)
		return;

	memset(obj->o_cksum, 0, sizeof(obj->o_cksum));
	obj->o_oid = htole64(oid);
	obj->o_xid = htole64(xid);
	obj->o_type = htole32(type);
	obj->o_subtype = htole32(subtype);
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

static bool
apfs_checkpoint_maps_valid(struct apfsmount *amp, const nx_superblock_t *nx,
    uint32_t desc_blocks, uint32_t desc_slot, uint64_t xid)
{
	struct buf *bp;
	checkpoint_map_phys_t *map;
	uint64_t desc_base, block_count;
	uint32_t desc_index, desc_len;
	uint32_t i, count, capacity;
	bool found_map = false, found_last = false;

	desc_base = le64toh(nx->nx_xp_desc_base);
	block_count = le64toh(nx->nx_block_count);
	desc_index = le32toh(nx->nx_xp_desc_index);
	desc_len = le32toh(nx->nx_xp_desc_len);
	if (desc_index >= desc_blocks || desc_slot >= desc_blocks ||
	    desc_len == 0 ||
	    desc_len > desc_blocks || desc_base >= block_count ||
	    desc_base > INT64_MAX || block_count > INT64_MAX ||
	    desc_blocks > block_count - desc_base) {
		printf("apfs_checkpoint: XID 0x%llx invalid descriptor ring "
		    "(base %llu blocks %u index %u length %u slot %u, "
		    "container blocks %llu)\n",
		    (unsigned long long)xid, (unsigned long long)desc_base,
		    desc_blocks, desc_index, desc_len, desc_slot,
		    (unsigned long long)block_count);
		return false;
	}
	if (((uint64_t)desc_index + desc_len - 1) % desc_blocks !=
	    desc_slot) {
		printf("apfs_checkpoint: XID 0x%llx descriptor slot mismatch "
		    "(index %u length %u slot %u, expected %llu)\n",
		    (unsigned long long)xid, desc_index, desc_len, desc_slot,
		    (unsigned long long)(((uint64_t)desc_index + desc_len - 1) %
		    desc_blocks));
		return false;
	}

	capacity = (amp->am_block_size - sizeof(*map)) /
	    sizeof(checkpoint_mapping_t);
	for (i = 0; i < desc_len; i++) {
		uint32_t index = ((uint64_t)desc_index + i) % desc_blocks;
		apfs_paddr_t paddr = (apfs_paddr_t)(desc_base + index);
		uint32_t flags;
		int error = apfs_bread(amp, paddr, &bp);

		if (error != 0) {
			printf("apfs_checkpoint: XID 0x%llx cannot read "
			    "descriptor block %llu: error %d\n",
			    (unsigned long long)xid, (unsigned long long)paddr,
			    error);
			return false;
		}
		map = (checkpoint_map_phys_t *)bp->b_data;
		if ((le32toh(map->cpm_o.o_type) & OBJECT_TYPE_MASK) !=
		    OBJ_CHECKPOINT_MAP ||
		    le64toh(map->cpm_o.o_xid) != xid) {
			if ((le32toh(map->cpm_o.o_type) & OBJECT_TYPE_MASK) ==
			    OBJ_CHECKPOINT_MAP) {
				printf("apfs_checkpoint: descriptor block %llu has "
				    "checkpoint-map XID 0x%llx, expected 0x%llx\n",
				    (unsigned long long)paddr,
				    (unsigned long long)le64toh(map->cpm_o.o_xid),
				    (unsigned long long)xid);
			}
			brelse(bp, 0);
			continue;
		}
		if (le64toh(map->cpm_o.o_oid) != (uint64_t)paddr) {
			printf("apfs_checkpoint: XID 0x%llx checkpoint-map at "
			    "%llu has OID 0x%llx, expected 0x%llx\n",
			    (unsigned long long)xid, (unsigned long long)paddr,
			    (unsigned long long)le64toh(map->cpm_o.o_oid),
			    (unsigned long long)paddr);
			brelse(bp, 0);
			return false;
		}
		if (!apfs_checksum_valid(amp, map)) {
			printf("apfs_checkpoint: XID 0x%llx checkpoint-map at "
			    "%llu has invalid checksum\n",
			    (unsigned long long)xid, (unsigned long long)paddr);
			brelse(bp, 0);
			return false;
		}

		count = le32toh(map->cpm_count);
		flags = le32toh(map->cpm_flags);
		if (count > capacity) {
			printf("apfs_checkpoint: XID 0x%llx checkpoint-map at "
			    "%llu has invalid entry count %u (capacity %u)\n",
			    (unsigned long long)xid, (unsigned long long)paddr,
			    count, capacity);
			brelse(bp, 0);
			return false;
		}
		printf("apfs_checkpoint: XID 0x%llx checkpoint-map at %llu "
		    "has %u entries, flags 0x%x\n",
		    (unsigned long long)xid, (unsigned long long)paddr, count,
		    flags);
		for (uint32_t j = 0; j < count; j++) {
			checkpoint_mapping_t *entry = &map->cpm_map[j];
			uint32_t size = le32toh(entry->cpm_size);
			uint64_t oid = le64toh(entry->cpm_oid);
			uint64_t mapping_paddr = le64toh(
			    (uint64_t)entry->cpm_paddr);
			uint32_t storage = le32toh(entry->cpm_type) &
			    OBJ_STORAGE_MASK;
			uint64_t blocks;

			if (oid == 0 || size == 0 || storage != OBJ_EPHEMERAL ||
			    mapping_paddr >= block_count) {
				printf("apfs_checkpoint: XID 0x%llx map block %llu "
				    "entry %u invalid (type 0x%x oid 0x%llx "
				    "size %u paddr %llu, container blocks %llu)\n",
				    (unsigned long long)xid,
				    (unsigned long long)paddr, j,
				    le32toh(entry->cpm_type),
				    (unsigned long long)oid, size,
				    (unsigned long long)mapping_paddr,
				    (unsigned long long)block_count);
				brelse(bp, 0);
				return false;
			}
			blocks = howmany(size, amp->am_block_size);
			if (blocks > block_count - mapping_paddr) {
				printf("apfs_checkpoint: XID 0x%llx map block %llu "
				    "entry %u extends past container "
				    "(size %u paddr %llu blocks %llu, "
				    "container blocks %llu)\n",
				    (unsigned long long)xid,
				    (unsigned long long)paddr, j, size,
				    (unsigned long long)mapping_paddr,
				    (unsigned long long)blocks,
				    (unsigned long long)block_count);
				brelse(bp, 0);
				return false;
			}

			/* Verify that mapped ephemeral object is present and valid */
			struct buf *mbp;
			int merror = apfs_bread(amp, (apfs_paddr_t)mapping_paddr, &mbp);
			if (merror != 0) {
				printf("apfs_checkpoint: XID 0x%llx cannot read "
				    "ephemeral block %llu: error %d\n",
				    (unsigned long long)xid,
				    (unsigned long long)mapping_paddr, merror);
				brelse(bp, 0);
				return false;
			}
			const obj_phys_t *obj = (const obj_phys_t *)mbp->b_data;
			if (le64toh(obj->o_oid) != oid || le64toh(obj->o_xid) != xid ||
			    !apfs_checksum_valid(amp, obj)) {
				printf("apfs_checkpoint: XID 0x%llx ephemeral block %llu "
				    "invalid (oid 0x%llx xid 0x%llx type 0x%x, expected oid 0x%llx xid 0x%llx)\n",
				    (unsigned long long)xid,
				    (unsigned long long)mapping_paddr,
				    (unsigned long long)le64toh(obj->o_oid),
				    (unsigned long long)le64toh(obj->o_xid),
				    le32toh(obj->o_type),
				    (unsigned long long)oid, (unsigned long long)xid);
				brelse(mbp, 0);
				brelse(bp, 0);
				return false;
			}
			brelse(mbp, 0);
		}
		found_map = true;
		found_last |= (flags & CHECKPOINT_MAP_LAST) != 0;
		brelse(bp, 0);
	}

	if (!found_map || !found_last) {
		printf("apfs_checkpoint: XID 0x%llx missing checkpoint map "
		    "(found map %u, found last %u)\n",
		    (unsigned long long)xid, found_map, found_last);
		return false;
	}
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
	printf("apfs_checkpoint: scanning descriptor ring base %llu "
	    "blocks %u (next xid 0x%llx)\n",
	    (unsigned long long)desc_base, desc_blocks,
	    (unsigned long long)le64toh(base.nx_next_xid));
	if (desc_blocks == 0 || desc_base > INT64_MAX ||
	    block_count > INT64_MAX || desc_base >= block_count ||
	    desc_blocks > block_count - desc_base) {
		printf("apfs_checkpoint: invalid descriptor ring in block-zero "
		    "superblock (base %llu blocks %u, container blocks %llu)\n",
		    (unsigned long long)desc_base, desc_blocks,
		    (unsigned long long)block_count);
		return EINVAL;
	}

	for (uint32_t i = 0; i < desc_blocks; i++) {
		uint64_t xid;
		uint32_t type;
		bool checksum_valid;

		error = apfs_bread(amp, (apfs_paddr_t)(desc_base + i), &bp);
		if (error != 0) {
			printf("apfs_checkpoint: cannot read descriptor slot %u "
			    "(block %llu): error %d\n", i,
			    (unsigned long long)(desc_base + i), error);
			continue;
		}
		memcpy(&candidate, bp->b_data, sizeof(candidate));
		type = le32toh(candidate.nx_o.o_type) & OBJECT_TYPE_MASK;
		xid = le64toh(candidate.nx_o.o_xid);
		if (type != OBJ_CONTAINER_SUPERBLOCK) {
			if (xid > selected_xid) {
				printf("apfs_checkpoint: skipping descriptor slot %u "
				    "(block %llu): object type 0x%x XID 0x%llx, "
				    "not a container superblock\n",
				    i, (unsigned long long)(desc_base + i),
				    type, (unsigned long long)xid);
			}
			brelse(bp, 0);
			continue;
		}
		if (xid <= selected_xid) {
			brelse(bp, 0);
			continue;
		}
		if (le32toh(candidate.nx_magic) != NX_MAGIC) {
			printf("apfs_checkpoint: rejecting candidate at block "
			    "%llu XID 0x%llx: magic 0x%x, expected 0x%x\n",
			    (unsigned long long)(desc_base + i),
			    (unsigned long long)xid,
			    le32toh(candidate.nx_magic), NX_MAGIC);
			brelse(bp, 0);
			continue;
		}
		if (le32toh(candidate.nx_block_size) != amp->am_block_size) {
			printf("apfs_checkpoint: rejecting candidate at block "
			    "%llu XID 0x%llx: block size %u, expected %u\n",
			    (unsigned long long)(desc_base + i),
			    (unsigned long long)xid,
			    le32toh(candidate.nx_block_size), amp->am_block_size);
			brelse(bp, 0);
			continue;
		}
		checksum_valid = apfs_checksum_valid(amp, bp->b_data);
		if (!checksum_valid) {
			printf("apfs_checkpoint: rejecting candidate at block "
			    "%llu XID 0x%llx: invalid checksum\n",
			    (unsigned long long)(desc_base + i),
			    (unsigned long long)xid);
			brelse(bp, 0);
			continue;
		}
		brelse(bp, 0);

		if (le32toh(candidate.nx_max_file_systems) >
		    NX_MAX_FILE_SYSTEMS) {
			printf("apfs_checkpoint: rejecting candidate at block "
			    "%llu XID 0x%llx: filesystem limit %u exceeds %u\n",
			    (unsigned long long)(desc_base + i),
			    (unsigned long long)xid,
			    le32toh(candidate.nx_max_file_systems),
			    NX_MAX_FILE_SYSTEMS);
			continue;
		}
		if (le64toh(candidate.nx_block_count) != block_count) {
			printf("apfs_checkpoint: rejecting candidate at block "
			    "%llu XID 0x%llx: block count %llu, expected %llu\n",
			    (unsigned long long)(desc_base + i),
			    (unsigned long long)xid,
			    (unsigned long long)le64toh(candidate.nx_block_count),
			    (unsigned long long)block_count);
			continue;
		}
		if (le64toh(candidate.nx_xp_desc_base) != desc_base) {
			printf("apfs_checkpoint: rejecting candidate at block "
			    "%llu XID 0x%llx: descriptor base %llu, expected %llu\n",
			    (unsigned long long)(desc_base + i),
			    (unsigned long long)xid,
			    (unsigned long long)le64toh(candidate.nx_xp_desc_base),
			    (unsigned long long)desc_base);
			continue;
		}
		if (le32toh(candidate.nx_xp_desc_blocks) != desc_blocks) {
			printf("apfs_checkpoint: rejecting candidate at block "
			    "%llu XID 0x%llx: descriptor blocks %u, expected %u\n",
			    (unsigned long long)(desc_base + i),
			    (unsigned long long)xid,
			    le32toh(candidate.nx_xp_desc_blocks), desc_blocks);
			continue;
		}
		if (!apfs_checkpoint_maps_valid(amp, &candidate, desc_blocks, i,
		    xid)) {
			printf("apfs_checkpoint: rejecting candidate at block "
			    "%llu XID 0x%llx: checkpoint maps invalid\n",
			    (unsigned long long)(desc_base + i),
			    (unsigned long long)xid);
			continue;
		}

		selected = candidate;
		selected_xid = xid;
		found = true;
		printf("apfs_checkpoint: accepted candidate at block %llu "
		    "XID 0x%llx\n", (unsigned long long)(desc_base + i),
		    (unsigned long long)xid);
	}

	if (!found)
		return EINVAL;

	amp->am_nx = selected;
	amp->am_desc_blocks = desc_blocks;
	amp->am_checkpoint_xid = selected_xid;
	return 0;
}

int
apfs_checkpoint_lookup(struct apfsmount *amp, oid_t oid, oid_t fs_oid,
    apfs_paddr_t *paddrp)
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

	capacity = (amp->am_block_size - sizeof(*map)) /
	    sizeof(checkpoint_mapping_t);
	for (uint32_t i = 0; i < desc_len; i++) {
		uint32_t index = ((uint64_t)desc_index + i) %
		    amp->am_desc_blocks;
		int error = apfs_bread(amp,
		    (apfs_paddr_t)(desc_base + index), &bp);
		if (error != 0)
			return error;
		map = (checkpoint_map_phys_t *)bp->b_data;
		if ((le32toh(map->cpm_o.o_type) & OBJECT_TYPE_MASK) !=
		    OBJ_CHECKPOINT_MAP ||
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
				*paddrp = (apfs_paddr_t)le64toh(
				    (uint64_t)entry->cpm_paddr);
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
	uint32_t struct_size, ip_bm_block_count;
	apfs_paddr_t ip_bm_base, ip_base;
	int free_bit_value = -1;
	bool have_clear_candidate = false, have_set_candidate = false;
	bool have_bitmap = false, have_unmapped_chunk = false;
	apfs_paddr_t spaceman_paddr;
	int error;

	amp->am_spaceman_write_safe = false;

	if (le64toh(amp->am_nx.nx_spaceman_oid) == 0)
		return EINVAL;
	error = apfs_checkpoint_lookup(amp,
	    le64toh(amp->am_nx.nx_spaceman_oid), 0, &spaceman_paddr);
	if (error != 0) {
		printf("apfs_spaceman: checkpoint lookup for OID 0x%llx "
		    "failed: error %d\n",
		    (unsigned long long)le64toh(amp->am_nx.nx_spaceman_oid),
		    error);
		return error;
	}
	if (!apfs_spaceman_paddr_valid(amp, spaceman_paddr)) {
		printf("apfs_spaceman: OID 0x%llx maps outside the container "
		    "(block %lld)\n",
		    (unsigned long long)le64toh(amp->am_nx.nx_spaceman_oid),
		    (long long)spaceman_paddr);
		return EINVAL;
	}
	error = apfs_bread(amp, spaceman_paddr, &smbp);
	if (error != 0) {
		printf("apfs_spaceman: cannot read object at block %lld: "
		    "error %d\n", (long long)spaceman_paddr, error);
		return error;
	}

	sm = (spaceman_phys_t *)smbp->b_data;
	if (!apfs_checksum_valid(amp, sm) ||
	    le64toh(sm->o.o_oid) !=
	    le64toh(amp->am_nx.nx_spaceman_oid) ||
	    le64toh(sm->o.o_xid) > amp->am_checkpoint_xid ||
	    (le32toh(sm->o.o_type) & OBJECT_TYPE_MASK) != OBJ_SPACEMAN) {
		printf("apfs_spaceman: invalid object header at block %lld "
		    "(oid 0x%llx xid 0x%llx type 0x%x)\n",
		    (long long)spaceman_paddr,
		    (unsigned long long)le64toh(sm->o.o_oid),
		    (unsigned long long)le64toh(sm->o.o_xid),
		    le32toh(sm->o.o_type));
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
		printf("apfs_spaceman: invalid geometry (block size %u/%u, "
		    "blocks %llu/%llu, chunks %llu, blocks/chunk %u, "
		    "chunks/CIB %u, CIBs %u, structure size %u)\n",
		    le32toh(sm->sm_block_size), amp->am_block_size,
		    (unsigned long long)block_count,
		    (unsigned long long)le64toh(amp->am_nx.nx_block_count),
		    (unsigned long long)chunk_count, blocks_per_chunk,
		    chunks_per_cib, cib_count, struct_size);
		brelse(smbp, 0);
		return EINVAL;
	}
	if (le32toh(dev->sm_cab_count) != 0 ||
	    le64toh(sm->sm_dev[1].sm_block_count) != 0 ||
	    le64toh(sm->sm_dev[1].sm_chunk_count) != 0 ||
	    le32toh(sm->sm_dev[1].sm_cib_count) != 0 ||
	    le32toh(sm->sm_dev[1].sm_cab_count) != 0) {
		printf("apfs_spaceman: CAB or secondary-device layout is not "
		    "supported by this validator\n");
		brelse(smbp, 0);
		return EOPNOTSUPP;
	}
	if (blocks_per_chunk > amp->am_block_size * 8U ||
	    chunks_per_cib >
	    (amp->am_block_size - sizeof(chunk_info_block_phys_t)) /
	    sizeof(chunk_info_phys_t) ||
	    addr_offset < sizeof(*sm) || addr_offset > amp->am_block_size ||
	    cib_count > (amp->am_block_size - addr_offset) / sizeof(uint64_t)) {
		printf("apfs_spaceman: invalid bitmap/CIB layout "
		    "(blocks/chunk %u, chunks/CIB %u, address offset %u, "
		    "CIB count %u, structure size %u)\n",
		    blocks_per_chunk, chunks_per_cib, addr_offset, cib_count,
		    struct_size);
		brelse(smbp, 0);
		return EINVAL;
	}
	expected_cib_count = chunk_count / chunks_per_cib +
	    (chunk_count % chunks_per_cib != 0);
	if (chunk_count != block_count / blocks_per_chunk +
	    (block_count % blocks_per_chunk != 0) ||
	    expected_cib_count != cib_count) {
		printf("apfs_spaceman: chunk geometry mismatch "
		    "(expected chunks %llu, CIBs %llu, found chunks %llu, "
		    "CIBs %u)\n",
		    (unsigned long long)(block_count / blocks_per_chunk +
		    (block_count % blocks_per_chunk != 0)),
		    (unsigned long long)expected_cib_count,
		    (unsigned long long)chunk_count, cib_count);
		brelse(smbp, 0);
		return EINVAL;
	}

	error = apfs_build_container_exclusions(amp, &excl_table);
	if (error != 0) {
		brelse(smbp, 0);
		return error;
	}

	ip_block_count = le64toh(sm->sm_ip_block_count);
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

	printf("apfs_spaceman: oid 0x%llx block size %u blocks %llu "
	    "chunks %llu blocks/chunk %u CIBs %u chunks/CIB %u\n",
	    (unsigned long long)le64toh(amp->am_nx.nx_spaceman_oid),
	    le32toh(sm->sm_block_size), (unsigned long long)block_count,
	    (unsigned long long)chunk_count, blocks_per_chunk, cib_count,
	    chunks_per_cib);

	for (uint32_t i = 0; i < cib_count; i++) {
		uint64_t cib_paddr_le;
		uint64_t cib_paddr;
		uint64_t first_chunk = (uint64_t)i * chunks_per_cib;
		uint64_t remaining_chunks = chunk_count - first_chunk;
		uint32_t expected_chunks = (uint32_t)MIN(
		    remaining_chunks, chunks_per_cib);
		chunk_info_block_phys_t *cib;

		memcpy(&cib_paddr_le, (uint8_t *)sm + addr_offset +
		    (size_t)i * sizeof(cib_paddr_le), sizeof(cib_paddr_le));
		cib_paddr = le64toh(cib_paddr_le);
		if (!apfs_spaceman_paddr_valid(amp, cib_paddr)) {
			printf("apfs_spaceman: CIB %u has invalid block address "
			    "%llu\n", i, (unsigned long long)cib_paddr);
			brelse(smbp, 0);
			return EINVAL;
		}
		error = apfs_bread(amp, (apfs_paddr_t)cib_paddr, &cibp);
		if (error != 0) {
			printf("apfs_spaceman: cannot read CIB %u at block %llu: "
			    "error %d\n", i, (unsigned long long)cib_paddr,
			    error);
			brelse(smbp, 0);
			return error;
		}
		cib = (chunk_info_block_phys_t *)cibp->b_data;
		if (!apfs_checksum_valid(amp, cib) ||
		    le64toh(cib->cib_o.o_oid) != cib_paddr ||
		    le64toh(cib->cib_o.o_xid) > amp->am_checkpoint_xid ||
		    (le32toh(cib->cib_o.o_type) & OBJECT_TYPE_MASK) !=
		    OBJ_SPACEMAN_CIB ||
		    le32toh(cib->cib_index) != i ||
		    le32toh(cib->cib_chunk_info_count) != expected_chunks) {
			printf("apfs_spaceman: invalid CIB %u at block %llu "
			    "(oid 0x%llx xid 0x%llx type 0x%x index %u "
			    "chunks %u, expected %u)\n",
			    i, (unsigned long long)cib_paddr,
			    (unsigned long long)le64toh(cib->cib_o.o_oid),
			    (unsigned long long)le64toh(cib->cib_o.o_xid),
			    le32toh(cib->cib_o.o_type),
			    le32toh(cib->cib_index),
			    le32toh(cib->cib_chunk_info_count),
			    expected_chunks);
			brelse(cibp, 0);
			brelse(smbp, 0);
			return EINVAL;
		}

		for (uint32_t j = 0; j < expected_chunks; j++) {
			chunk_info_phys_t ci;
			uint64_t chunk_index = first_chunk + j;
			uint64_t chunk_start = chunk_index * blocks_per_chunk;
			uint64_t blocks_remaining = block_count - chunk_start;
			uint32_t expected_blocks = (uint32_t)MIN(
			    blocks_remaining, blocks_per_chunk);
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
				printf("apfs_spaceman: invalid chunk %llu "
				    "(xid 0x%llx address %llu/%llu blocks %u/%u "
				    "free %u)\n",
				    (unsigned long long)chunk_index,
				    (unsigned long long)le64toh(ci.ci_xid),
				    (unsigned long long)le64toh(ci.ci_addr),
				    (unsigned long long)chunk_start,
				    ci_block_count, expected_blocks, ci_free_count);
				brelse(cibp, 0);
				brelse(smbp, 0);
				return EINVAL;
			}
			if (bitmap_paddr == 0) {
				if (ci_free_count != expected_blocks) {
					printf("apfs_spaceman: chunk %llu has no "
					    "bitmap but reports %u/%u free blocks\n",
					    (unsigned long long)chunk_index,
					    ci_free_count, expected_blocks);
					brelse(cibp, 0);
					brelse(smbp, 0);
					return EINVAL;
				}
				free_blocks = expected_blocks;
				have_unmapped_chunk = true;
			} else {
				if (!apfs_spaceman_paddr_valid(amp,
				    bitmap_paddr) ||
				    bitmap_paddr == cib_paddr) {
					printf("apfs_spaceman: chunk %llu has invalid "
					    "bitmap block %llu\n",
					    (unsigned long long)chunk_index,
					    (unsigned long long)bitmap_paddr);
					brelse(cibp, 0);
					brelse(smbp, 0);
					return EINVAL;
				}
				error = apfs_bread(amp,
				    (apfs_paddr_t)bitmap_paddr, &bitmap_bp);
				if (error != 0) {
					printf("apfs_spaceman: cannot read bitmap for "
					    "chunk %llu at block %llu: error %d\n",
					    (unsigned long long)chunk_index,
					    (unsigned long long)bitmap_paddr,
					    error);
					brelse(cibp, 0);
					brelse(smbp, 0);
					return error;
				}
				const uint8_t *bitmap =
				    (const uint8_t *)bitmap_bp->b_data;
				uint32_t clear_blocks = 0, set_blocks = 0;
				uint32_t first_clear = expected_blocks;
				uint32_t first_set = expected_blocks;

				have_bitmap = true;
				for (uint32_t bit = 0; bit < expected_blocks; bit++) {
					uint64_t block_paddr = chunk_start + bit;
					bool is_safe = apfs_spaceman_candidate_safe(amp,
					    &excl_table, block_paddr);

					/* APFS numbers bitmap bits from the LSB. */
					if ((bitmap[bit >> 3] &
					    (1U << (bit & 7))) == 0) {
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
				if (first_clear < expected_blocks &&
				    !have_clear_candidate) {
					first_clear_free = chunk_start + first_clear;
					first_clear_bitmap = bitmap_paddr;
					first_clear_chunk = chunk_index;
					first_clear_bit = first_clear;
					have_clear_candidate = true;
				}
				if (first_set < expected_blocks &&
				    !have_set_candidate) {
					first_set_free = chunk_start + first_set;
					first_set_bitmap = bitmap_paddr;
					first_set_chunk = chunk_index;
					first_set_bit = first_set;
					have_set_candidate = true;
				}
				if (clear_blocks == ci_free_count &&
				    set_blocks != ci_free_count) {
					if (free_bit_value == 1) {
						printf("apfs_spaceman: bitmap polarity "
						    "conflicts at chunk %llu\n",
						    (unsigned long long)chunk_index);
						brelse(cibp, 0);
						brelse(smbp, 0);
						return EINVAL;
					}
					free_bit_value = 0;
				} else if (set_blocks == ci_free_count &&
				    clear_blocks != ci_free_count) {
					if (free_bit_value == 0) {
						printf("apfs_spaceman: bitmap polarity "
						    "conflicts at chunk %llu\n",
						    (unsigned long long)chunk_index);
						brelse(cibp, 0);
						brelse(smbp, 0);
						return EINVAL;
					}
					free_bit_value = 1;
				} else if (clear_blocks != ci_free_count ||
				    set_blocks != ci_free_count) {
					printf("apfs_spaceman: chunk %llu bitmap "
					    "counts clear=%u set=%u disagree with "
					    "CIB free count %u\n",
					    (unsigned long long)chunk_index,
					    clear_blocks, set_blocks, ci_free_count);
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
		printf("apfs_spaceman: chunk free total %llu disagrees with "
		    "device free count %llu\n",
		    (unsigned long long)total_free,
		    (unsigned long long)le64toh(dev->sm_free_count));
		brelse(smbp, 0);
		return EINVAL;
	}

	printf("apfs_spaceman: validated %llu free blocks across %llu chunks\n",
	    (unsigned long long)total_free,
	    (unsigned long long)chunk_count);
	if (active_fq_entries > 0) {
		printf("apfs_spaceman: active free queues contain %llu delayed free entries\n",
		    (unsigned long long)active_fq_entries);
	}
	if (free_bit_value == 0 && have_clear_candidate) {
		printf("apfs_spaceman: bitmap semantics: clear bits are free; "
		    "read-only candidate %llu (chunk %llu, bitmap %llu, "
		    "bit %u; not reserved)\n",
		    (unsigned long long)first_clear_free,
		    (unsigned long long)first_clear_chunk,
		    (unsigned long long)first_clear_bitmap, first_clear_bit);
	} else if (free_bit_value == 1 && have_set_candidate) {
		printf("apfs_spaceman: bitmap semantics: set bits are free; "
		    "read-only candidate %llu (chunk %llu, bitmap %llu, "
		    "bit %u; not reserved)\n",
		    (unsigned long long)first_set_free,
		    (unsigned long long)first_set_chunk,
		    (unsigned long long)first_set_bitmap, first_set_bit);
	} else if (total_free == 0) {
		printf("apfs_spaceman: no free-block candidate found\n");
	} else if (have_bitmap) {
		printf("apfs_spaceman: free counts validate, but bitmap polarity "
		    "is ambiguous; no candidate reported\n");
	} else if (have_unmapped_chunk) {
		printf("apfs_spaceman: free chunks lack allocation bitmaps; "
		    "no safe candidate reported\n");
	}
	amp->am_spaceman_write_safe = free_bit_value == 0;
	brelse(smbp, 0);
	return 0;
}

/* OMap resolution: virtual OID -> physical block address */
static int apfs_omap_lookup_internal(struct apfsmount *, apfs_tx_t *, oid_t,
    oid_t, xid_t, apfs_paddr_t *);

static int
apfs_omap_object_paddr(struct apfsmount *amp, apfs_tx_t *tx, oid_t omap_oid,
    xid_t xid, apfs_paddr_t *paddrp)
{
	apfs_paddr_t paddr;
	int error;

	if (tx != NULL) {
		for (uint32_t i = 0; i < tx->tx_omap_count; i++) {
			if (tx->tx_omaps[i].os_oid == omap_oid) {
				*paddrp = tx->tx_omaps[i].os_paddr;
				return 0;
			}
		}
		for (uint32_t i = 0; i < tx->tx_map_count; i++) {
			checkpoint_mapping_t *entry = &tx->tx_mappings[i];

			if (le64toh(entry->cpm_oid) == omap_oid) {
				*paddrp = (apfs_paddr_t)le64toh(
				    (uint64_t)entry->cpm_paddr);
				return 0;
			}
		}
	}

	error = apfs_checkpoint_lookup(amp, omap_oid, 0, &paddr);
	if (error == ENOENT)
		paddr = (apfs_paddr_t)omap_oid;
	else if (error != 0)
		return error;

	if (paddr < 0 ||
	    (uint64_t)paddr >= le64toh(amp->am_nx.nx_block_count) ||
	    (uint64_t)paddr > INT64_MAX)
		return EINVAL;
	*paddrp = paddr;
	return 0;
}

static int
apfs_omap_lookup_internal(struct apfsmount *amp, apfs_tx_t *tx,
    oid_t omap_oid, oid_t oid, xid_t xid, apfs_paddr_t *paddrp)
{
    struct buf *bp;
    apfs_paddr_t omap_paddr;
    omap_phys_t *omap;
    omap_key_t key;
    omap_key_t found_key;
    omap_val_t val;
    uint64_t calculated_cksum, stored_cksum;
    uint64_t block_count;
    uint32_t tree_type;
    int error;

    if (amp == NULL || omap_oid == 0 || oid == 0 || paddrp == NULL) {
        printf("apfs_omap_lookup: omap_oid is 0\n");
        return EINVAL;
    }

    error = apfs_omap_object_paddr(amp, tx, omap_oid, xid, &omap_paddr);
    if (error != 0)
        return error;
    error = apfs_bread(amp, omap_paddr, &bp);
    if (error != 0)
        return error;

    omap = (omap_phys_t *)bp->b_data;
    calculated_cksum = apfs_fletcher64(bp->b_data, amp->am_block_size);
    memcpy(&stored_cksum, omap->omap_o.o_cksum, sizeof(stored_cksum));
    stored_cksum = le64toh(stored_cksum);
    if (calculated_cksum != stored_cksum) {
        printf("apfs_omap_lookup: OMap checksum mismatch at APFS block "
            "%llu: calculated 0x%016llx, disk 0x%016llx\n",
            (unsigned long long)omap_paddr,
            (unsigned long long)calculated_cksum,
            (unsigned long long)stored_cksum);
        brelse(bp, 0);
        return EINVAL;
    }
    if (le64toh(omap->omap_o.o_oid) != omap_oid ||
        le64toh(omap->omap_o.o_xid) > xid ||
        (le32toh(omap->omap_o.o_type) & OBJECT_TYPE_MASK) != OBJ_OMAP) {
        printf("apfs_omap_lookup: invalid OMap object at APFS block %llu "
            "(oid 0x%llx type 0x%x)\n",
            (unsigned long long)omap_paddr,
            (unsigned long long)le64toh(omap->omap_o.o_oid),
            le32toh(omap->omap_o.o_type));
        brelse(bp, 0);
        return EINVAL;
    }

    oid_t tree_oid = le64toh(omap->omap_tree_oid);
    tree_type = le32toh(omap->omap_tree_type);
    brelse(bp, 0);
    if (tree_oid == 0) {
        printf("apfs_omap_lookup: OMap object at APFS block %llu has no "
            "tree root\n", (unsigned long long)omap_oid);
        return EINVAL;
    }

    key.ok_oid = htole64(oid);
    key.ok_xid = htole64(xid);
    printf("apfs_omap_lookup: search oid 0x%llx xid 0x%llx in tree "
        "0x%llx (tree type 0x%x)\n", (unsigned long long)oid,
        (unsigned long long)xid, (unsigned long long)tree_oid,
        tree_type);
    error = apfs_btree_search(amp, 0, tree_oid, &key, sizeof(key), &val,
        sizeof(val), &found_key, sizeof(found_key), NULL);
    if (error == 0) {
        uint32_t flags = le32toh(val.ov_flags);
        uint64_t paddr = le64toh((uint64_t)val.ov_paddr);

        printf("apfs_omap_lookup: result requested (0x%llx,0x%llx), "
            "found (0x%llx,0x%llx) flags 0x%x size %u paddr %llu\n",
            (unsigned long long)oid, (unsigned long long)xid,
            (unsigned long long)le64toh(found_key.ok_oid),
            (unsigned long long)le64toh(found_key.ok_xid), flags,
            le32toh(val.ov_size), (unsigned long long)paddr);
        if (flags & OMAP_VAL_DELETED)
            return ENOENT;
        if (flags & OMAP_VAL_ENCRYPTED) {
            printf("apfs_omap_lookup: encrypted object 0x%llx requires "
                "key-based decryption, which is not available\n",
                (unsigned long long)oid);
            return EOPNOTSUPP;
        }
        block_count = le64toh(amp->am_nx.nx_block_count);
        if (paddr == tree_oid) {
            printf("apfs_omap_lookup: oid 0x%llx maps to its OMap tree "
                "root 0x%llx (found key oid 0x%llx xid 0x%llx, "
                "flags 0x%x, size %u)\n",
                (unsigned long long)oid, (unsigned long long)tree_oid,
                (unsigned long long)le64toh(found_key.ok_oid),
                (unsigned long long)le64toh(found_key.ok_xid), flags,
                le32toh(val.ov_size));
        }
        if (paddr == 0 || paddr >= block_count) {
            printf("apfs_omap_lookup: invalid mapping for oid 0x%llx "
                "at requested xid 0x%llx (found xid 0x%llx, flags 0x%x, "
                "size %u, paddr %llu, block count %llu)\n",
                (unsigned long long)oid, (unsigned long long)xid,
                (unsigned long long)le64toh(found_key.ok_xid), flags,
                le32toh(val.ov_size), (unsigned long long)paddr,
                (unsigned long long)block_count);
            return EINVAL;
        }
        *paddrp = (apfs_paddr_t)paddr;
    } else {
        printf("apfs_omap_lookup: tree at APFS block %llu has no mapping "
            "for oid 0x%llx at xid 0x%llx (error %d)\n",
            (unsigned long long)tree_oid, (unsigned long long)oid,
            (unsigned long long)xid, error);
    }
    return error;
}

int
apfs_omap_lookup(struct apfsmount *amp, oid_t omap_oid, oid_t oid, xid_t xid,
    apfs_paddr_t *paddrp)
{
	return apfs_omap_lookup_internal(amp, NULL, omap_oid, oid, xid, paddrp);
}

static int
apfs_key_compare(uint32_t type, const void *k1, size_t k1_len, const void *k2, size_t k2_len)
{
    if ((type & OBJECT_TYPE_MASK) == OBJ_OMAP) {
        const omap_key_t *ok1 = k1;
        const omap_key_t *ok2 = k2;
        uint64_t oid1, oid2, xid1, xid2;

        if (k1_len < sizeof(*ok1) || k2_len < sizeof(*ok2))
            return 0;
        oid1 = le64toh(ok1->ok_oid);
        oid2 = le64toh(ok2->ok_oid);
        if (oid1 < oid2) return -1;
        if (oid1 > oid2) return 1;
        xid1 = le64toh(ok1->ok_xid);
        xid2 = le64toh(ok2->ok_xid);
        if (xid1 < xid2) return -1;
        if (xid1 > xid2) return 1;
        return 0;
    }

    uint64_t kt1 = le64toh(*(const uint64_t *)k1);
    uint64_t kt2 = le64toh(*(const uint64_t *)k2);

    uint64_t oid1 = kt1 & OBJ_ID_MASK;
    uint64_t oid2 = kt2 & OBJ_ID_MASK;
    if (oid1 < oid2) return -1;
    if (oid1 > oid2) return 1;

    uint32_t type1 = (kt1 & OBJ_TYPE_MASK) >> OBJ_TYPE_SHIFT;
    uint32_t type2 = (kt2 & OBJ_TYPE_MASK) >> OBJ_TYPE_SHIFT;
    if (type1 < type2) return -1;
    if (type1 > type2) return 1;

    /* Type and OID match, check subtypes */
    uint32_t subtype = type1;

    if (subtype == APFS_TYPE_DIR_REC) {
        if (k1_len < 12 || k2_len < 12) return 0; /* Should not happen for full keys */
        const j_drec_key_t *dk1 = k1;
        const j_drec_key_t *dk2 = k2;
        uint32_t nh1 = le32toh(dk1->name_len_and_hash);
        uint32_t nh2 = le32toh(dk2->name_len_and_hash);
        uint32_t h1 = nh1 & DREC_HASH_MASK;
        uint32_t h2 = nh2 & DREC_HASH_MASK;

        if (h1 < h2) return -1;
        if (h1 > h2) return 1;

        uint32_t len1 = nh1 & DREC_NLEN_MASK;
        uint32_t len2 = nh2 & DREC_NLEN_MASK;
        int len = MIN(len1, len2);
        int cmp = memcmp(dk1->name, dk2->name, len);
        if (cmp != 0) return cmp;
        if (len1 < len2) return -1;
        if (len1 > len2) return 1;
    } else if (subtype == APFS_TYPE_EXTENT) {
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
    apfs_tx_t *tx, xid_t xid, uint32_t tree_flags, oid_t child_oid,
    apfs_paddr_t *paddrp)
{
	oid_t fs_oid;

	if (tree_flags & BTREE_PHYSICAL) {
		if (child_oid > INT64_MAX)
			return EINVAL;
		*paddrp = (apfs_paddr_t)child_oid;
		return 0;
	}
	if (tree_flags & BTREE_EPHEMERAL) {
		fs_oid = omap_oid == 0 ? 0 :
		    le64toh(amp->am_sb.apfs_o.o_oid);
		return apfs_checkpoint_lookup(amp, child_oid, fs_oid, paddrp);
	}
	if (omap_oid == 0)
		return EINVAL;
	return apfs_omap_lookup_internal(amp, tx, omap_oid, child_oid, xid,
	    paddrp);
}

/* B-Tree search implementation */
int
apfs_btree_search(struct apfsmount *amp, oid_t omap_oid, oid_t tree_oid,
    void *key, size_t key_len, void *val, size_t val_size, void *found_key,
    size_t found_key_size, size_t *found_val_size)
{
    struct buf *bp;
    btree_node_phys_t *node;
    apfs_paddr_t paddr;
    btree_info_t info;
    uint32_t tree_flags = 0;
    uint32_t tree_subtype = 0;
    bool have_info = false;
    uint64_t node_limit = 0;
    uint64_t steps = 0;
    uint8_t expected_hash[BTREE_NODE_HASH_SIZE_MAX];
    uint8_t calculated_hash[BTREE_NODE_HASH_SIZE_MAX];
    bool have_expected_hash = false;
    int error;

    if (key_len == 0 || key_len > amp->am_block_size || val == NULL ||
        val_size == 0 || val_size > amp->am_block_size ||
        (found_key != NULL && found_key_size == 0))
        return EINVAL;
    if (found_val_size != NULL)
        *found_val_size = 0;

    /* 1. Resolve tree root OID to physical address */
    if (tree_oid == omap_oid || omap_oid == 0) {
        paddr = tree_oid; 
    } else {
        error = apfs_omap_lookup(amp, omap_oid, tree_oid,
            amp->am_checkpoint_xid, &paddr);
        if (error)
            return error;
    }

    /* 2. Read and traverse nodes */
    while (1) {
        error = apfs_bread(amp, paddr, &bp);
        if (error) return error;

        node = (btree_node_phys_t *)bp->b_data;
        uint16_t node_flags = le16toh(node->btn_flags);
        uint32_t node_type = le32toh(node->btn_o.o_type) &
            OBJECT_TYPE_MASK;
        uint32_t nkeys = le32toh(node->btn_nkeys);
        if ((node_flags & BTNODE_ROOT) != 0) {
            memcpy(&info, (uint8_t *)node + amp->am_block_size -
                sizeof(info), sizeof(info));
            tree_flags = le32toh(info.bt_flags);
            node_limit = le64toh(info.bt_node_count);
            have_info = true;
            tree_subtype = (node_flags & BTNODE_NOHEADER) ?
                OBJ_FSTREE : le32toh(node->btn_o.o_subtype);
            if ((tree_flags & (BTREE_PHYSICAL | BTREE_EPHEMERAL)) ==
                (BTREE_PHYSICAL | BTREE_EPHEMERAL) ||
                ((tree_flags & (BTREE_HASHED | BTREE_NOHEADER)) != 0 &&
                (tree_flags & (BTREE_HASHED | BTREE_NOHEADER)) !=
                (BTREE_HASHED | BTREE_NOHEADER)) ||
                le32toh(info.bt_node_size) != amp->am_block_size ||
                node_limit == 0) {
                brelse(bp, 0);
                return EOPNOTSUPP;
            }
            if ((tree_flags & BTREE_HASHED) != 0) {
                if (!amp->am_sealed ||
                    (node_flags & BTNODE_NOHEADER) == 0) {
                    brelse(bp, 0);
                    return EOPNOTSUPP;
                }
                memcpy(expected_hash, amp->am_root_hash,
                    sizeof(expected_hash));
                have_expected_hash = true;
            } else if ((node_flags & BTNODE_NOHEADER) != 0 ||
                node_type != OBJ_BTREE) {
                printf("apfs_btree_search: invalid root node for tree "
                    "0x%llx at block %lld (type 0x%x flags 0x%x "
                    "subtype 0x%x)\n",
                    (unsigned long long)tree_oid, (long long)paddr,
                    node_type, node_flags, tree_subtype);
                brelse(bp, 0);
                return EINVAL;
            }
        } else if (!have_info ||
            (((tree_flags & BTREE_HASHED) == 0) &&
            node_type != OBJ_BTREE_NODE) ||
            (((tree_flags & BTREE_HASHED) != 0) &&
            ((node_flags & BTNODE_NOHEADER) == 0))) {
            printf("apfs_btree_search: invalid child node for tree "
                "0x%llx at block %lld (type 0x%x flags 0x%x "
                "subtype 0x%x tree flags 0x%x)\n",
                (unsigned long long)tree_oid, (long long)paddr,
                node_type, node_flags, tree_subtype, tree_flags);
            brelse(bp, 0);
            return EINVAL;
        }
        if ((tree_flags & BTREE_HASHED) != 0 &&
            (node_flags & BTNODE_LEAF) == 0 &&
            (node_flags & BTNODE_HASHED) == 0) {
            printf("apfs_btree_search: unhashed internal node in hashed "
                "tree 0x%llx at block %lld (flags 0x%x)\n",
                (unsigned long long)tree_oid, (long long)paddr,
                node_flags);
            brelse(bp, 0);
            return EINVAL;
        }
        if ((tree_flags & BTREE_HASHED) != 0) {
            if (!have_expected_hash ||
                apfs_hash_data(amp, node, amp->am_block_size,
                calculated_hash) != 0 ||
                memcmp(calculated_hash, expected_hash,
                amp->am_hash_size) != 0) {
                brelse(bp, 0);
                return EAUTH;
            }
            have_expected_hash = false;
        } else if (!apfs_checksum_valid(amp, node)) {
            printf("apfs_btree_search: invalid checksum for tree "
                "0x%llx node at block %lld (type 0x%x oid 0x%llx)\n",
                (unsigned long long)tree_oid, (long long)paddr,
                node_type,
                (unsigned long long)le64toh(node->btn_o.o_oid));
            brelse(bp, 0);
            return EINVAL;
        }
        if (++steps > node_limit + 1 || nkeys == 0) {
            printf("apfs_btree_search: invalid node count for tree "
                "0x%llx at block %lld (steps %llu limit %llu keys %u)\n",
                (unsigned long long)tree_oid, (long long)paddr,
                (unsigned long long)steps,
                (unsigned long long)node_limit, nkeys);
            brelse(bp, 0);
            return EINVAL;
        }

        int low = 0, high = (int)nkeys - 1;
        int mid, last_match = -1, cmp;
        const void *k_ptr, *v_ptr;
        size_t k_len = 0, v_len = 0;

        while (low <= high) {
            mid = (low + high) / 2;
            error = apfs_btree_entry(amp, node, &info, mid, &k_ptr,
                &k_len, &v_ptr, &v_len);
            if (error != 0) {
                printf("apfs_btree_search: invalid entry %d in tree "
                    "0x%llx node block %lld: error %d\n", mid,
                    (unsigned long long)tree_oid, (long long)paddr,
                    error);
                brelse(bp, 0);
                return error;
            }
            cmp = apfs_key_compare(tree_subtype,
                key, key_len, k_ptr, k_len);
            if (cmp == 0) {
                last_match = mid;
                break;
            } else if (cmp < 0) {
                high = mid - 1;
            } else {
                low = mid + 1;
            }
        }

        if (node_flags & BTNODE_LEAF) {
            if (last_match == -1)
                last_match = (low > 0) ? low - 1 : 0;
            error = apfs_btree_entry(amp, node, &info, last_match,
                &k_ptr, &k_len, &v_ptr, &v_len);
            if (error != 0) {
                printf("apfs_btree_search: invalid selected entry %d in "
                    "tree 0x%llx node block %lld: error %d\n",
                    last_match, (unsigned long long)tree_oid,
                    (long long)paddr, error);
                brelse(bp, 0);
                return error;
            }
            int match_error = 0;
            if ((tree_subtype & OBJECT_TYPE_MASK) ==
                OBJ_OMAP) {
                const omap_key_t *requested = key;
                const omap_key_t *found = k_ptr;

                if (le64toh(requested->ok_oid) != le64toh(found->ok_oid) ||
                    le64toh(found->ok_xid) > le64toh(requested->ok_xid))
                    match_error = ENOENT;
            } else if (((le64toh(*(uint64_t *)key) & OBJ_TYPE_MASK) >>
                OBJ_TYPE_SHIFT) ==
                APFS_TYPE_EXTENT) {
                if (apfs_key_compare(
                    tree_subtype, key, key_len, k_ptr,
                    k_len) < 0)
                    match_error = ENOENT;
            } else {
                if (apfs_key_compare(
                    tree_subtype, key, key_len, k_ptr,
                    k_len) != 0)
                    match_error = ENOENT;
            }
            if (match_error != 0) {
                brelse(bp, 0);
                return match_error;
            }
            if (found_val_size == NULL && v_len < val_size) {
                printf("apfs_btree_search: value too short in tree "
                    "0x%llx node block %lld entry %d (%zu < %zu)\n",
                    (unsigned long long)tree_oid, (long long)paddr,
                    last_match, v_len, val_size);
                brelse(bp, 0);
                return EINVAL;
            }
            if (found_val_size != NULL && v_len > val_size) {
                brelse(bp, 0);
                return EOVERFLOW;
            }
            memset(val, 0, val_size);
            memcpy(val, v_ptr, v_len);
            if (found_val_size != NULL)
                *found_val_size = v_len;
            if (found_key != NULL) {
                if (k_len > found_key_size) {
                    brelse(bp, 0);
                    return EOVERFLOW;
                }
                memcpy(found_key, k_ptr, k_len);
            }
            brelse(bp, 0);
            return 0;
        } else {
            mid = last_match != -1 ? last_match :
                (low > 0 ? low - 1 : 0);
            error = apfs_btree_entry(amp, node, &info, mid, &k_ptr,
                &k_len, &v_ptr, &v_len);
            if (error != 0 ||
                v_len < ((tree_flags & BTREE_HASHED) != 0 ?
                sizeof(btree_index_node_val_t) : sizeof(oid_t))) {
                printf("apfs_btree_search: invalid child entry %d in "
                    "tree 0x%llx node block %lld (error %d value size "
                    "%zu tree flags 0x%x)\n", mid,
                    (unsigned long long)tree_oid, (long long)paddr,
                    error, v_len, tree_flags);
                brelse(bp, 0);
                return error != 0 ? error : EINVAL;
            }
            oid_t child_oid = le64toh(*(const oid_t *)v_ptr);
            if ((tree_flags & BTREE_HASHED) != 0) {
                const btree_index_node_val_t *index_val = v_ptr;
                memcpy(expected_hash, index_val->child_hash,
                    sizeof(expected_hash));
                have_expected_hash = true;
            }
            brelse(bp, 0);
            error = apfs_btree_resolve_child(amp, omap_oid, NULL,
                amp->am_checkpoint_xid, tree_flags, child_oid, &paddr);
            if (error != 0) {
                printf("apfs_btree_search: cannot resolve child 0x%llx "
                    "of tree 0x%llx: error %d\n",
                    (unsigned long long)child_oid,
                    (unsigned long long)tree_oid, error);
                return error;
            }
        }
    }
}

int
apfs_btree_iterate(struct apfsmount *amp, oid_t omap_oid, oid_t tree_oid, void *start_key, size_t key_len, apfs_btree_iter_cb cb, void *arg)
{
	struct apfs_btree_iter_frame {
		apfs_paddr_t paddr;
		uint32_t next_child;
		bool is_root;
		bool initialized;
		bool have_expected_hash;
		uint8_t expected_hash[BTREE_NODE_HASH_SIZE_MAX];
	};
	struct apfs_btree_iter_frame *stack;
	struct buf *bp;
	btree_node_phys_t *node;
	btree_info_t info;
	apfs_paddr_t root_paddr;
	uint32_t tree_flags, tree_subtype;
	uint64_t node_count, visited_nodes = 1;
	uint8_t calculated_hash[BTREE_NODE_HASH_SIZE_MAX];
	size_t depth = 0;
	int error;

	if (key_len > amp->am_block_size)
		return EINVAL;
	if (amp->am_hash_size > sizeof(calculated_hash))
		return EINVAL;

	stack = kmem_alloc(sizeof(*stack) * APFS_BTREE_MAX_DEPTH, KM_SLEEP);
	root_paddr = tree_oid;
	if (tree_oid != omap_oid && omap_oid != 0) {
		error = apfs_omap_lookup(amp, omap_oid, tree_oid,
		    amp->am_checkpoint_xid, &root_paddr);
		if (error)
			goto out;
	}

	error = apfs_bread(amp, root_paddr, &bp);
	if (error)
		goto out;
	node = (btree_node_phys_t *)bp->b_data;
	uint16_t root_flags = le16toh(node->btn_flags);
	if ((root_flags & BTNODE_ROOT) == 0) {
		brelse(bp, 0);
		error = EINVAL;
		goto out;
	}
	memcpy(&info, (uint8_t *)node + amp->am_block_size - sizeof(info),
	    sizeof(info));
	tree_flags = le32toh(info.bt_flags);
	tree_subtype = (root_flags & BTNODE_NOHEADER) ? OBJ_FSTREE :
	    le32toh(node->btn_o.o_subtype);
	node_count = le64toh(info.bt_node_count);
	if ((tree_flags & (BTREE_PHYSICAL | BTREE_EPHEMERAL)) ==
	    (BTREE_PHYSICAL | BTREE_EPHEMERAL) ||
	    (((tree_flags & (BTREE_HASHED | BTREE_NOHEADER)) != 0) &&
	    (tree_flags & (BTREE_HASHED | BTREE_NOHEADER)) !=
	    (BTREE_HASHED | BTREE_NOHEADER)) ||
	    le32toh(info.bt_node_size) != amp->am_block_size ||
	    node_count == 0) {
		brelse(bp, 0);
		error = EOPNOTSUPP;
		goto out;
	}
	if ((tree_flags & BTREE_HASHED) != 0) {
		if (!amp->am_sealed || (root_flags & BTNODE_NOHEADER) == 0) {
			brelse(bp, 0);
			error = EOPNOTSUPP;
			goto out;
		}
	} else if ((root_flags & BTNODE_NOHEADER) != 0 ||
	    (le32toh(node->btn_o.o_type) & OBJECT_TYPE_MASK) != OBJ_BTREE) {
		brelse(bp, 0);
		error = EINVAL;
		goto out;
	}
	brelse(bp, 0);

	memset(&stack[0], 0, sizeof(stack[0]));
	stack[0].paddr = root_paddr;
	stack[0].is_root = true;
	if ((tree_flags & BTREE_HASHED) != 0) {
		memcpy(stack[0].expected_hash, amp->am_root_hash,
		    sizeof(stack[0].expected_hash));
		stack[0].have_expected_hash = true;
	}
	depth = 1;
	error = 0;

	while (depth != 0) {
		struct apfs_btree_iter_frame *frame = &stack[depth - 1];
		uint16_t node_flags;
		uint32_t nkeys;

		error = apfs_bread(amp, frame->paddr, &bp);
		if (error)
			goto out;
		node = (btree_node_phys_t *)bp->b_data;
		node_flags = le16toh(node->btn_flags);
		nkeys = le32toh(node->btn_nkeys);

		if (frame->is_root != ((node_flags & BTNODE_ROOT) != 0) ||
		    (!frame->is_root &&
		    (((tree_flags & BTREE_HASHED) == 0 &&
		    (le32toh(node->btn_o.o_type) & OBJECT_TYPE_MASK) !=
		    OBJ_BTREE_NODE) ||
		    ((tree_flags & BTREE_HASHED) != 0 &&
		    (node_flags & BTNODE_NOHEADER) == 0)))) {
			brelse(bp, 0);
			error = EINVAL;
			goto out;
		}
		if ((tree_flags & BTREE_HASHED) != 0 &&
		    (node_flags & BTNODE_LEAF) == 0 &&
		    (node_flags & BTNODE_HASHED) == 0) {
			brelse(bp, 0);
			error = EINVAL;
			goto out;
		}
		if ((tree_flags & BTREE_HASHED) != 0) {
			if (!frame->have_expected_hash ||
			    apfs_hash_data(amp, node, amp->am_block_size,
			    calculated_hash) != 0 ||
			    memcmp(calculated_hash, frame->expected_hash,
			    amp->am_hash_size) != 0) {
				brelse(bp, 0);
				error = EAUTH;
				goto out;
			}
		} else if (!apfs_checksum_valid(amp, node)) {
			brelse(bp, 0);
			error = EINVAL;
			goto out;
		}

		if ((node_flags & BTNODE_LEAF) != 0) {
			uint32_t i;

			printf("apfs_btree_iterate: tree 0x%llx visiting leaf "
			    "%lld with %u entries\n",
			    (unsigned long long)tree_oid,
			    (long long)frame->paddr, nkeys);
			for (i = 0; i < nkeys; i++) {
				const void *k_ptr, *v_ptr;
				size_t k_len, v_len;

				error = apfs_btree_entry(amp, node, &info, i,
				    &k_ptr, &k_len, &v_ptr, &v_len);
				if (error)
					break;
				if (apfs_key_compare(tree_subtype, k_ptr, k_len,
				    start_key, key_len) < 0)
					continue;
				error = cb(arg, k_ptr, k_len, v_ptr, v_len);
				if (error)
					break;
			}
			brelse(bp, 0);
			if (error)
				goto out;
			depth--;
			continue;
		}

		if (!frame->initialized) {
			int low = 0, high = (int)nkeys - 1;

			while (low <= high) {
				int mid = (low + high) / 2;
				const void *index_key, *index_val;
				size_t index_key_len, index_val_len;

				error = apfs_btree_entry(amp, node, &info, mid,
				    &index_key, &index_key_len, &index_val,
				    &index_val_len);
				if (error) {
					brelse(bp, 0);
					goto out;
				}
				if (apfs_key_compare(tree_subtype, start_key,
				    key_len, index_key, index_key_len) < 0)
					high = mid - 1;
				else
					low = mid + 1;
			}
			frame->next_child = low > 0 ? low - 1 : 0;
			frame->initialized = true;
		}

		if (frame->next_child >= nkeys) {
			brelse(bp, 0);
			depth--;
			continue;
		}

		const void *k_ptr, *v_ptr;
		size_t k_len, v_len;
		error = apfs_btree_entry(amp, node, &info, frame->next_child++,
		    &k_ptr, &k_len, &v_ptr, &v_len);
		if (error ||
		    v_len < ((tree_flags & BTREE_HASHED) != 0 ?
		    sizeof(btree_index_node_val_t) : sizeof(oid_t))) {
			brelse(bp, 0);
			if (error == 0)
				error = EINVAL;
			goto out;
		}

		oid_t child_oid;
		memcpy(&child_oid, v_ptr, sizeof(child_oid));
		child_oid = le64toh(child_oid);
		uint8_t child_hash[BTREE_NODE_HASH_SIZE_MAX];
		bool child_has_hash = (tree_flags & BTREE_HASHED) != 0;
		if (child_has_hash) {
			const btree_index_node_val_t *index_val = v_ptr;

			memcpy(child_hash, index_val->child_hash,
			    sizeof(child_hash));
		}
		brelse(bp, 0);

		if (depth >= APFS_BTREE_MAX_DEPTH) {
			error = ELOOP;
			goto out;
		}
		if (++visited_nodes > node_count) {
			error = EINVAL;
			goto out;
		}
		memset(&stack[depth], 0, sizeof(stack[depth]));
		error = apfs_btree_resolve_child(amp, omap_oid, NULL,
		    amp->am_checkpoint_xid, tree_flags, child_oid,
		    &stack[depth].paddr);
		if (error)
			goto out;
		if (child_has_hash) {
			memcpy(stack[depth].expected_hash, child_hash,
			    sizeof(child_hash));
			stack[depth].have_expected_hash = true;
		}
		depth++;
	}

	error = 0;
out:
	kmem_free(stack, sizeof(*stack) * APFS_BTREE_MAX_DEPTH);
	printf("apfs_btree_iterate: tree 0x%llx returning error %d\n",
	    (unsigned long long)tree_oid, error);
	return error;
}

struct apfs_btree_entry_ref {
	void *key;
	size_t key_len;
	void *val;
	size_t val_len;
};

static int
apfs_btree_write_node_entries(struct apfsmount *amp, void *node_buf, uint16_t flags,
    uint16_t level, const struct apfs_btree_entry_ref *entries, uint32_t nentries,
    const btree_info_t *info)
{
	btree_node_phys_t *node = (btree_node_phys_t *)node_buf;
	memset(node_buf, 0, amp->am_block_size);
	node->btn_flags = htole16(flags);
	node->btn_level = htole16(level);
	node->btn_nkeys = htole32(nentries);

	uint32_t toc_size = (flags & BTNODE_FIXED_KV_SIZE) ?
	    sizeof(btree_toc_fixed_entry_t) : sizeof(btree_toc_entry_t);
	uint32_t table_len = nentries * toc_size;
	node->btn_table_space_off = htole16(0);
	node->btn_table_space_len = htole16(table_len);

	uint8_t *data = (uint8_t *)node + sizeof(*node);
	uint32_t key_area_start = sizeof(*node) + table_len;
	uint32_t data_end = amp->am_block_size - ((flags & BTNODE_ROOT) ? sizeof(btree_info_t) : 0);
	uint32_t curr_key_off = 0;
	uint32_t curr_val_off = 0;

	for (uint32_t i = 0; i < nentries; i++) {
		if (key_area_start > data_end ||
		    curr_key_off > data_end - key_area_start ||
		    entries[i].key_len > data_end - key_area_start - curr_key_off ||
		    curr_val_off > data_end ||
		    entries[i].val_len > data_end - curr_val_off ||
		    curr_val_off + entries[i].val_len > data_end - key_area_start - curr_key_off - entries[i].key_len) {
			return ENOSPC;
		}

		memcpy((uint8_t *)node + key_area_start + curr_key_off, entries[i].key, entries[i].key_len);
		curr_val_off += entries[i].val_len;
		memcpy((uint8_t *)node + data_end - curr_val_off, entries[i].val, entries[i].val_len);

		if (flags & BTNODE_FIXED_KV_SIZE) {
			btree_toc_fixed_entry_t *toc = (btree_toc_fixed_entry_t *)(data);
			toc[i].key_off = htole16(curr_key_off);
			toc[i].val_off = htole16(curr_val_off);
		} else {
			btree_toc_entry_t *toc = (btree_toc_entry_t *)(data);
			toc[i].key_off = htole16(curr_key_off);
			toc[i].key_len = htole16(entries[i].key_len);
			toc[i].val_off = htole16(curr_val_off);
			toc[i].val_len = htole16(entries[i].val_len);
		}

		curr_key_off += entries[i].key_len;
	}

	if (flags & BTNODE_ROOT) {
		btree_info_t *rinfo = (btree_info_t *)((char *)node + amp->am_block_size - sizeof(btree_info_t));
		memcpy(rinfo, info, sizeof(*rinfo));
	}

	return 0;
}

static void
apfs_btree_free_entry_refs(struct apfs_btree_entry_ref *entries, uint32_t count)
{
	if (entries == NULL)
		return;
	for (uint32_t k = 0; k < count; k++) {
		if (entries[k].key != NULL && entries[k].key_len > 0)
			kmem_free(entries[k].key, entries[k].key_len);
		if (entries[k].val != NULL && entries[k].val_len > 0)
			kmem_free(entries[k].val, entries[k].val_len);
	}
	kmem_free(entries, sizeof(*entries) * count);
}

/* B-Tree Insertion with COW Cascade & Node Splitting */
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
	if (omap_oid != 0 && *tree_oid != omap_oid) {
		error = apfs_omap_lookup_internal(amp, tx, omap_oid, *tree_oid,
		    tx->tx_xid, &root_paddr);
		if (error != 0)
			return error;
	} else {
		root_paddr = (apfs_paddr_t)*tree_oid;
	}

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
			/* Leaf node found: find insertion index */
			uint32_t ins_idx = nkeys;
			bool is_replace = false;
			for (uint32_t i = 0; i < nkeys; i++) {
				const void *k_ptr, *v_ptr;
				size_t k_len, v_len;
				error = apfs_btree_entry(amp, node, &info, i, &k_ptr, &k_len, &v_ptr, &v_len);
				if (error != 0) {
					brelse(bp, 0);
					return error;
				}
				uint32_t subtype = (tree_flags & BTREE_HASHED) ? APFS_TYPE_ANY :
				    ((flags & BTNODE_FIXED_KV_SIZE) ? OBJ_OMAP : OBJ_FSTREE);
				int cmp = apfs_key_compare(subtype, key, key_len, k_ptr, k_len);
				if (cmp == 0) {
					ins_idx = i;
					is_replace = true;
					break;
				} else if (cmp < 0) {
					ins_idx = i;
					break;
				}
			}
			path.bp_entries[path.bp_depth].pe_idx = ins_idx;
			path.bp_entries[path.bp_depth].pe_flags = flags | (is_replace ? 0x8000 : 0);
			path.bp_depth++;
			brelse(bp, 0);
			break;
		}

		/* Internal node: find child whose index key <= requested key */
		uint32_t child_idx = 0;
		for (uint32_t i = 0; i < nkeys; i++) {
			const void *k_ptr, *v_ptr;
			size_t k_len, v_len;
			error = apfs_btree_entry(amp, node, &info, i, &k_ptr, &k_len, &v_ptr, &v_len);
			if (error != 0) {
				brelse(bp, 0);
				return error;
			}
			uint32_t subtype = (flags & BTNODE_FIXED_KV_SIZE) ? OBJ_OMAP : OBJ_FSTREE;
			if (apfs_key_compare(subtype, key, key_len, k_ptr, k_len) >= 0)
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

		error = apfs_btree_resolve_child(amp, omap_oid, tx, tx->tx_xid,
		    tree_flags, child_oid, &curr_paddr);
		if (error != 0)
			return error;

		path.bp_depth++;
	}

	if (path.bp_depth == 0)
		return EINVAL;

	/* 2. Insert into leaf node with Copy-on-Write and Node Splitting */
	uint32_t leaf_depth = path.bp_depth - 1;
	apfs_paddr_t old_leaf_paddr = path.bp_entries[leaf_depth].pe_paddr;
	uint32_t ins_idx = path.bp_entries[leaf_depth].pe_idx;

	error = apfs_bread(amp, old_leaf_paddr, &bp);
	if (error != 0)
		return error;

	btree_node_phys_t *old_leaf = (btree_node_phys_t *)bp->b_data;
	bool is_replace = (path.bp_entries[leaf_depth].pe_flags & 0x8000) != 0;
	uint16_t leaf_flags = le16toh(old_leaf->btn_flags) & ~0x8000;
	uint32_t old_nkeys = le32toh(old_leaf->btn_nkeys);
	uint32_t leaf_type = le32toh(old_leaf->btn_o.o_type);
	uint32_t leaf_subtype = le32toh(old_leaf->btn_o.o_subtype);
	uint32_t new_nkeys = is_replace ? old_nkeys : (old_nkeys + 1);

	struct apfs_btree_entry_ref *all_entries = kmem_alloc(sizeof(*all_entries) * new_nkeys, KM_SLEEP);
	for (uint32_t i = 0; i < new_nkeys; i++) {
		const void *k_ptr, *v_ptr;
		size_t k_sz, v_sz;
		if (i == ins_idx) {
			k_ptr = key;
			k_sz = key_len;
			v_ptr = val;
			v_sz = val_len;
		} else {
			uint32_t src_i = is_replace ? i : ((i < ins_idx) ? i : i - 1);
			error = apfs_btree_entry(amp, old_leaf, &info, src_i,
			    &k_ptr, &k_sz, &v_ptr, &v_sz);
			if (error != 0) {
				brelse(bp, 0);
				apfs_btree_free_entry_refs(all_entries, i);
				return error;
			}
		}
		void *k_copy = kmem_alloc(k_sz, KM_SLEEP);
		memcpy(k_copy, k_ptr, k_sz);
		all_entries[i].key = k_copy;
		all_entries[i].key_len = k_sz;

		void *v_copy = kmem_alloc(v_sz, KM_SLEEP);
		memcpy(v_copy, v_ptr, v_sz);
		all_entries[i].val = v_copy;
		all_entries[i].val_len = v_sz;
	}
	brelse(bp, 0);

	btree_info_t new_info = info;
	if (!is_replace)
		new_info.bt_key_count = htole64(le64toh(info.bt_key_count) + 1);

	apfs_paddr_t new_leaf_paddr;
	error = apfs_tx_alloc_block(tx, 1, &new_leaf_paddr);
	if (error != 0) {
		apfs_btree_free_entry_refs(all_entries, new_nkeys);
		return error;
	}

	struct buf *new_bp;
	error = apfs_getblk(amp, new_leaf_paddr, &new_bp);
	if (error != 0) {
		apfs_btree_free_entry_refs(all_entries, new_nkeys);
		return error;
	}

	int write_err = apfs_btree_write_node_entries(amp, new_bp->b_data, leaf_flags,
	    le16toh(old_leaf->btn_level), all_entries, new_nkeys, &new_info);

	if (write_err == 0) {
		/* Node fits without split */
		btree_node_phys_t *new_leaf = (btree_node_phys_t *)new_bp->b_data;
		leaf_type = (leaf_type & ~OBJECT_TYPE_MASK) |
		    ((leaf_flags & BTNODE_ROOT) ? OBJ_BTREE : OBJ_BTREE_NODE);
		apfs_obj_init(&new_leaf->btn_o, (oid_t)new_leaf_paddr, tx->tx_xid,
		    leaf_type, leaf_subtype);
		apfs_obj_set_cksum(amp, new_leaf);
		error = apfs_bwrite(amp, new_leaf_paddr, new_bp);
		if (error != 0) {
			apfs_btree_free_entry_refs(all_entries, new_nkeys);
			return error;
		}

		/* 3. Propagate up the path stack if internal nodes exist */
		apfs_paddr_t child_paddr = new_leaf_paddr;
		for (int d = (int)leaf_depth - 1; d >= 0; d--) {
			apfs_paddr_t old_parent_paddr = path.bp_entries[d].pe_paddr;
			uint32_t p_child_idx = path.bp_entries[d].pe_idx;

			error = apfs_bread(amp, old_parent_paddr, &bp);
			if (error != 0) {
				apfs_btree_free_entry_refs(all_entries, new_nkeys);
				return error;
			}

			btree_node_phys_t *old_parent = (btree_node_phys_t *)bp->b_data;
			uint16_t p_flags = le16toh(old_parent->btn_flags);
			uint32_t parent_type = le32toh(old_parent->btn_o.o_type);
			uint32_t parent_subtype = le32toh(old_parent->btn_o.o_subtype);

			apfs_paddr_t new_parent_paddr;
			error = apfs_tx_alloc_block(tx, 1, &new_parent_paddr);
			if (error != 0) {
				brelse(bp, 0);
				apfs_btree_free_entry_refs(all_entries, new_nkeys);
				return error;
			}

			error = apfs_getblk(amp, new_parent_paddr, &new_bp);
			if (error != 0) {
				brelse(bp, 0);
				apfs_btree_free_entry_refs(all_entries, new_nkeys);
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
				if (!is_replace)
					p_info->bt_key_count = htole32(le32toh(p_info->bt_key_count) + 1);
			}

			parent_type = (parent_type & ~OBJECT_TYPE_MASK) |
			    ((p_flags & BTNODE_ROOT) ? OBJ_BTREE : OBJ_BTREE_NODE);
			apfs_obj_init(&new_parent->btn_o, (oid_t)new_parent_paddr,
			    tx->tx_xid, parent_type, parent_subtype);
			apfs_obj_set_cksum(amp, new_parent);

			error = apfs_bwrite(amp, new_parent_paddr, new_bp);
			if (error != 0) {
				apfs_btree_free_entry_refs(all_entries, new_nkeys);
				return error;
			}

			child_paddr = new_parent_paddr;
		}

		if (omap_oid != 0 && *tree_oid != omap_oid) {
			error = apfs_omap_update(tx, omap_oid, *tree_oid, child_paddr);
			if (error != 0) {
				apfs_btree_free_entry_refs(all_entries, new_nkeys);
				return error;
			}
		} else {
			*tree_oid = (oid_t)child_paddr;
		}

		apfs_btree_free_entry_refs(all_entries, new_nkeys);
		return 0;
	}

	/* 4. Split node */
	uint32_t mid = new_nkeys / 2;
	if (leaf_flags & BTNODE_ROOT) {
		/* Root split: allocate left, right, and new root */
		brelse(new_bp, 0);

		apfs_paddr_t left_paddr, right_paddr, new_root_paddr;
		error = apfs_tx_alloc_block(tx, 1, &left_paddr);
		if (error != 0) {
			apfs_btree_free_entry_refs(all_entries, new_nkeys);
			return error;
		}
		error = apfs_tx_alloc_block(tx, 1, &right_paddr);
		if (error != 0) {
			apfs_btree_free_entry_refs(all_entries, new_nkeys);
			return error;
		}
		error = apfs_tx_alloc_block(tx, 1, &new_root_paddr);
		if (error != 0) {
			apfs_btree_free_entry_refs(all_entries, new_nkeys);
			return error;
		}

		struct buf *left_bp, *right_bp, *root_bp;
		error = apfs_getblk(amp, left_paddr, &left_bp);
		if (error != 0) {
			apfs_btree_free_entry_refs(all_entries, new_nkeys);
			return error;
		}
		error = apfs_getblk(amp, right_paddr, &right_bp);
		if (error != 0) {
			brelse(left_bp, 0);
			apfs_btree_free_entry_refs(all_entries, new_nkeys);
			return error;
		}
		error = apfs_getblk(amp, new_root_paddr, &root_bp);
		if (error != 0) {
			brelse(left_bp, 0);
			brelse(right_bp, 0);
			apfs_btree_free_entry_refs(all_entries, new_nkeys);
			return error;
		}

		uint16_t child_flags = (leaf_flags & ~BTNODE_ROOT) | BTNODE_LEAF;
		uint32_t child_type = (leaf_type & ~OBJECT_TYPE_MASK) | OBJ_BTREE_NODE;

		apfs_btree_write_node_entries(amp, left_bp->b_data, child_flags, 0,
		    &all_entries[0], mid, NULL);
		apfs_obj_init(&((btree_node_phys_t *)left_bp->b_data)->btn_o,
		    (oid_t)left_paddr, tx->tx_xid, child_type, leaf_subtype);
		apfs_obj_set_cksum(amp, left_bp->b_data);
		apfs_bwrite(amp, left_paddr, left_bp);

		apfs_btree_write_node_entries(amp, right_bp->b_data, child_flags, 0,
		    &all_entries[mid], new_nkeys - mid, NULL);
		apfs_obj_init(&((btree_node_phys_t *)right_bp->b_data)->btn_o,
		    (oid_t)right_paddr, tx->tx_xid, child_type, leaf_subtype);
		apfs_obj_set_cksum(amp, right_bp->b_data);
		apfs_bwrite(amp, right_paddr, right_bp);

		/* Elevate root */
		btree_info_t root_info = info;
		root_info.bt_node_count = htole64(le64toh(info.bt_node_count) + 2);
		if (!is_replace)
			root_info.bt_key_count = htole64(le64toh(info.bt_key_count) + 1);

		oid_t left_val = htole64((uint64_t)left_paddr);
		oid_t right_val = htole64((uint64_t)right_paddr);

		struct apfs_btree_entry_ref root_entries[2];
		root_entries[0].key = all_entries[0].key;
		root_entries[0].key_len = all_entries[0].key_len;
		root_entries[0].val = &left_val;
		root_entries[0].val_len = sizeof(left_val);

		root_entries[1].key = all_entries[mid].key;
		root_entries[1].key_len = all_entries[mid].key_len;
		root_entries[1].val = &right_val;
		root_entries[1].val_len = sizeof(right_val);

		uint16_t root_flags = (leaf_flags & ~BTNODE_LEAF) | BTNODE_ROOT;
		uint32_t r_type = (leaf_type & ~OBJECT_TYPE_MASK) | OBJ_BTREE;

		apfs_btree_write_node_entries(amp, root_bp->b_data, root_flags, 1,
		    root_entries, 2, &root_info);
		apfs_obj_init(&((btree_node_phys_t *)root_bp->b_data)->btn_o,
		    (oid_t)new_root_paddr, tx->tx_xid, r_type, leaf_subtype);
		apfs_obj_set_cksum(amp, root_bp->b_data);
		apfs_bwrite(amp, new_root_paddr, root_bp);

		if (omap_oid != 0 && *tree_oid != omap_oid) {
			error = apfs_omap_update(tx, omap_oid, *tree_oid, new_root_paddr);
		} else {
			*tree_oid = (oid_t)new_root_paddr;
		}
		apfs_btree_free_entry_refs(all_entries, new_nkeys);
		return error;
	} else {
		/* Non-root leaf split */
		apfs_paddr_t left_paddr = new_leaf_paddr;
		apfs_paddr_t right_paddr;
		error = apfs_tx_alloc_block(tx, 1, &right_paddr);
		if (error != 0) {
			brelse(new_bp, 0);
			apfs_btree_free_entry_refs(all_entries, new_nkeys);
			return error;
		}

		struct buf *right_bp;
		error = apfs_getblk(amp, right_paddr, &right_bp);
		if (error != 0) {
			brelse(new_bp, 0);
			apfs_btree_free_entry_refs(all_entries, new_nkeys);
			return error;
		}

		uint16_t child_flags = (leaf_flags & ~BTNODE_ROOT) | BTNODE_LEAF;
		uint32_t child_type = (leaf_type & ~OBJECT_TYPE_MASK) | OBJ_BTREE_NODE;

		apfs_btree_write_node_entries(amp, new_bp->b_data, child_flags, 0,
		    &all_entries[0], mid, NULL);
		apfs_obj_init(&((btree_node_phys_t *)new_bp->b_data)->btn_o,
		    (oid_t)left_paddr, tx->tx_xid, child_type, leaf_subtype);
		apfs_obj_set_cksum(amp, new_bp->b_data);
		apfs_bwrite(amp, left_paddr, new_bp);

		apfs_btree_write_node_entries(amp, right_bp->b_data, child_flags, 0,
		    &all_entries[mid], new_nkeys - mid, NULL);
		apfs_obj_init(&((btree_node_phys_t *)right_bp->b_data)->btn_o,
		    (oid_t)right_paddr, tx->tx_xid, child_type, leaf_subtype);
		apfs_obj_set_cksum(amp, right_bp->b_data);
		apfs_bwrite(amp, right_paddr, right_bp);

		/* Propagate split up to parent */
		apfs_paddr_t child_paddr = left_paddr;
		apfs_paddr_t split_right_paddr = right_paddr;
		void *split_pivot_key = kmem_alloc(all_entries[mid].key_len, KM_SLEEP);
		memcpy(split_pivot_key, all_entries[mid].key, all_entries[mid].key_len);
		size_t split_pivot_key_len = all_entries[mid].key_len;
		bool child_was_split = true;

		for (int d = (int)leaf_depth - 1; d >= 0; d--) {
			apfs_paddr_t old_parent_paddr = path.bp_entries[d].pe_paddr;
			uint32_t p_child_idx = path.bp_entries[d].pe_idx;

			error = apfs_bread(amp, old_parent_paddr, &bp);
			if (error != 0) {
				kmem_free(split_pivot_key, split_pivot_key_len);
				apfs_btree_free_entry_refs(all_entries, new_nkeys);
				return error;
			}

			btree_node_phys_t *old_parent = (btree_node_phys_t *)bp->b_data;
			uint16_t p_flags = le16toh(old_parent->btn_flags);
			uint16_t p_level = le16toh(old_parent->btn_level);
			uint32_t p_nkeys = le32toh(old_parent->btn_nkeys);
			uint32_t parent_type = le32toh(old_parent->btn_o.o_type);
			uint32_t parent_subtype = le32toh(old_parent->btn_o.o_subtype);

			uint32_t new_p_nkeys = p_nkeys + (child_was_split ? 1 : 0);
			struct apfs_btree_entry_ref *p_entries = kmem_alloc(sizeof(*p_entries) * new_p_nkeys, KM_SLEEP);

			oid_t left_val = htole64((uint64_t)child_paddr);
			oid_t right_val = htole64((uint64_t)split_right_paddr);

			for (uint32_t j = 0; j < new_p_nkeys; j++) {
				const void *k_ptr, *v_ptr;
				size_t k_sz, v_sz;
				if (j < p_child_idx) {
					apfs_btree_entry(amp, old_parent, &info, j, &k_ptr, &k_sz, &v_ptr, &v_sz);
				} else if (j == p_child_idx) {
					apfs_btree_entry(amp, old_parent, &info, j, &k_ptr, &k_sz, &v_ptr, &v_sz);
					v_ptr = &left_val;
					v_sz = sizeof(left_val);
				} else if (child_was_split && j == p_child_idx + 1) {
					k_ptr = split_pivot_key;
					k_sz = split_pivot_key_len;
					v_ptr = &right_val;
					v_sz = sizeof(right_val);
				} else {
					uint32_t src_j = child_was_split ? j - 1 : j;
					apfs_btree_entry(amp, old_parent, &info, src_j, &k_ptr, &k_sz, &v_ptr, &v_sz);
				}
				void *k_copy = kmem_alloc(k_sz, KM_SLEEP);
				memcpy(k_copy, k_ptr, k_sz);
				p_entries[j].key = k_copy;
				p_entries[j].key_len = k_sz;
				void *v_copy = kmem_alloc(v_sz, KM_SLEEP);
				memcpy(v_copy, v_ptr, v_sz);
				p_entries[j].val = v_copy;
				p_entries[j].val_len = v_sz;
			}
			brelse(bp, 0);

			apfs_paddr_t new_p_paddr;
			error = apfs_tx_alloc_block(tx, 1, &new_p_paddr);
			if (error != 0) {
				apfs_btree_free_entry_refs(p_entries, new_p_nkeys);
				kmem_free(split_pivot_key, split_pivot_key_len);
				apfs_btree_free_entry_refs(all_entries, new_nkeys);
				return error;
			}

			struct buf *new_p_bp;
			error = apfs_getblk(amp, new_p_paddr, &new_p_bp);
			if (error != 0) {
				apfs_btree_free_entry_refs(p_entries, new_p_nkeys);
				kmem_free(split_pivot_key, split_pivot_key_len);
				apfs_btree_free_entry_refs(all_entries, new_nkeys);
				return error;
			}

			btree_info_t p_info = info;
			p_info.bt_node_count = htole64(le64toh(info.bt_node_count) + 1);
			if (!is_replace)
				p_info.bt_key_count = htole64(le64toh(info.bt_key_count) + 1);

			int p_write_err = apfs_btree_write_node_entries(amp, new_p_bp->b_data,
			    p_flags, p_level, p_entries, new_p_nkeys, &p_info);

			if (p_write_err == 0) {
				btree_node_phys_t *new_parent = (btree_node_phys_t *)new_p_bp->b_data;
				parent_type = (parent_type & ~OBJECT_TYPE_MASK) |
				    ((p_flags & BTNODE_ROOT) ? OBJ_BTREE : OBJ_BTREE_NODE);
				apfs_obj_init(&new_parent->btn_o, (oid_t)new_p_paddr, tx->tx_xid,
				    parent_type, parent_subtype);
				apfs_obj_set_cksum(amp, new_parent);
				apfs_bwrite(amp, new_p_paddr, new_p_bp);

				child_paddr = new_p_paddr;
				child_was_split = false;
				apfs_btree_free_entry_refs(p_entries, new_p_nkeys);
			} else {
				/* Parent also needs to split */
				brelse(new_p_bp, 0);

				uint32_t p_mid = new_p_nkeys / 2;
				if (p_flags & BTNODE_ROOT) {
					apfs_paddr_t p_left_paddr, p_right_paddr, p_root_paddr;
					apfs_tx_alloc_block(tx, 1, &p_left_paddr);
					apfs_tx_alloc_block(tx, 1, &p_right_paddr);
					apfs_tx_alloc_block(tx, 1, &p_root_paddr);

					struct buf *p_left_bp, *p_right_bp, *p_root_bp;
					apfs_getblk(amp, p_left_paddr, &p_left_bp);
					apfs_getblk(amp, p_right_paddr, &p_right_bp);
					apfs_getblk(amp, p_root_paddr, &p_root_bp);

					uint16_t p_child_flags = p_flags & ~BTNODE_ROOT;
					uint32_t p_child_type = (parent_type & ~OBJECT_TYPE_MASK) | OBJ_BTREE_NODE;

					apfs_btree_write_node_entries(amp, p_left_bp->b_data, p_child_flags, p_level,
					    &p_entries[0], p_mid, NULL);
					apfs_obj_init(&((btree_node_phys_t *)p_left_bp->b_data)->btn_o,
					    (oid_t)p_left_paddr, tx->tx_xid, p_child_type, parent_subtype);
					apfs_obj_set_cksum(amp, p_left_bp->b_data);
					apfs_bwrite(amp, p_left_paddr, p_left_bp);

					apfs_btree_write_node_entries(amp, p_right_bp->b_data, p_child_flags, p_level,
					    &p_entries[p_mid], new_p_nkeys - p_mid, NULL);
					apfs_obj_init(&((btree_node_phys_t *)p_right_bp->b_data)->btn_o,
					    (oid_t)p_right_paddr, tx->tx_xid, p_child_type, parent_subtype);
					apfs_obj_set_cksum(amp, p_right_bp->b_data);
					apfs_bwrite(amp, p_right_paddr, p_right_bp);

					btree_info_t p_root_info = info;
					p_root_info.bt_node_count = htole64(le64toh(info.bt_node_count) + 3);
					if (!is_replace)
						p_root_info.bt_key_count = htole64(le64toh(info.bt_key_count) + 1);

					oid_t p_left_val = htole64((uint64_t)p_left_paddr);
					oid_t p_right_val = htole64((uint64_t)p_right_paddr);

					struct apfs_btree_entry_ref p_root_entries[2];
					p_root_entries[0].key = p_entries[0].key;
					p_root_entries[0].key_len = p_entries[0].key_len;
					p_root_entries[0].val = &p_left_val;
					p_root_entries[0].val_len = sizeof(p_left_val);

					p_root_entries[1].key = p_entries[p_mid].key;
					p_root_entries[1].key_len = p_entries[p_mid].key_len;
					p_root_entries[1].val = &p_right_val;
					p_root_entries[1].val_len = sizeof(p_right_val);

					uint16_t p_root_flags = (p_flags & ~BTNODE_LEAF) | BTNODE_ROOT;
					uint32_t p_r_type = (parent_type & ~OBJECT_TYPE_MASK) | OBJ_BTREE;

					apfs_btree_write_node_entries(amp, p_root_bp->b_data, p_root_flags, p_level + 1,
					    p_root_entries, 2, &p_root_info);
					apfs_obj_init(&((btree_node_phys_t *)p_root_bp->b_data)->btn_o,
					    (oid_t)p_root_paddr, tx->tx_xid, p_r_type, parent_subtype);
					apfs_obj_set_cksum(amp, p_root_bp->b_data);
					apfs_bwrite(amp, p_root_paddr, p_root_bp);

					child_paddr = p_root_paddr;
					child_was_split = false;
				}
				apfs_btree_free_entry_refs(p_entries, new_p_nkeys);
			}
		}

		kmem_free(split_pivot_key, split_pivot_key_len);
		if (omap_oid != 0 && *tree_oid != omap_oid) {
			error = apfs_omap_update(tx, omap_oid, *tree_oid, child_paddr);
		} else {
			*tree_oid = (oid_t)child_paddr;
		}
		apfs_btree_free_entry_refs(all_entries, new_nkeys);
		return error;
	}
}

/* B-Tree Deletion with COW Cascade */
int
apfs_btree_remove_record(apfs_tx_t *tx, oid_t omap_oid, oid_t *tree_oid,
    const void *key, size_t key_len)
{
	struct apfsmount *amp;
	apfs_paddr_t root_paddr, curr_paddr;
	apfs_btree_path_t path;
	struct buf *bp;
	btree_info_t info;
	uint32_t tree_flags = 0;
	int error;

	if (tx == NULL || tx->tx_amp == NULL || tree_oid == NULL || key == NULL)
		return EINVAL;

	amp = tx->tx_amp;
	if (omap_oid != 0 && *tree_oid != omap_oid) {
		error = apfs_omap_lookup_internal(amp, tx, omap_oid, *tree_oid,
		    tx->tx_xid, &root_paddr);
		if (error != 0)
			return error;
	} else {
		root_paddr = (apfs_paddr_t)*tree_oid;
	}

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
			/* Leaf node found: search for matching key */
			uint32_t del_idx = nkeys;
			uint32_t subtype = (tree_flags & BTREE_HASHED) ? APFS_TYPE_ANY :
			    ((flags & BTNODE_FIXED_KV_SIZE) ? OBJ_OMAP : OBJ_FSTREE);

			for (uint32_t i = 0; i < nkeys; i++) {
				const void *k_ptr, *v_ptr;
				size_t k_len, v_len;
				error = apfs_btree_entry(amp, node, &info, i, &k_ptr, &k_len, &v_ptr, &v_len);
				if (error != 0) {
					brelse(bp, 0);
					return error;
				}
				if (apfs_key_compare(subtype, key, key_len, k_ptr, k_len) == 0) {
					del_idx = i;
					break;
				}
			}
			if (del_idx == nkeys) {
				brelse(bp, 0);
				return ENOENT;
			}
			path.bp_entries[path.bp_depth].pe_idx = del_idx;
			path.bp_depth++;
			brelse(bp, 0);
			break;
		}

		/* Internal node: find child */
		uint32_t child_idx = 0;
		for (uint32_t i = 0; i < nkeys; i++) {
			const void *k_ptr, *v_ptr;
			size_t k_len, v_len;
			error = apfs_btree_entry(amp, node, &info, i, &k_ptr, &k_len, &v_ptr, &v_len);
			if (error != 0) {
				brelse(bp, 0);
				return error;
			}
			uint32_t subtype = (flags & BTNODE_FIXED_KV_SIZE) ? OBJ_OMAP : OBJ_FSTREE;
			if (apfs_key_compare(subtype, key, key_len, k_ptr, k_len) >= 0)
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

		error = apfs_btree_resolve_child(amp, omap_oid, tx, tx->tx_xid,
		    tree_flags, child_oid, &curr_paddr);
		if (error != 0)
			return error;

		path.bp_depth++;
	}

	if (path.bp_depth == 0)
		return EINVAL;

	/* 2. Remove from leaf node with Copy-on-Write */
	uint32_t leaf_depth = path.bp_depth - 1;
	apfs_paddr_t old_leaf_paddr = path.bp_entries[leaf_depth].pe_paddr;
	uint32_t del_idx = path.bp_entries[leaf_depth].pe_idx;

	error = apfs_bread(amp, old_leaf_paddr, &bp);
	if (error != 0)
		return error;

	btree_node_phys_t *old_leaf = (btree_node_phys_t *)bp->b_data;
	uint16_t leaf_flags = le16toh(old_leaf->btn_flags);
	uint32_t old_nkeys = le32toh(old_leaf->btn_nkeys);
	uint32_t table_off = le16toh(old_leaf->btn_table_space_off);
	uint32_t table_len = le16toh(old_leaf->btn_table_space_len);
	uint32_t leaf_type = le32toh(old_leaf->btn_o.o_type);
	uint32_t leaf_subtype = le32toh(old_leaf->btn_o.o_subtype);
	uint32_t data_end = amp->am_block_size - ((leaf_flags & BTNODE_ROOT) ? sizeof(btree_info_t) : 0);
	uint32_t toc_size = (leaf_flags & BTNODE_FIXED_KV_SIZE) ?
	    sizeof(btree_toc_fixed_entry_t) : sizeof(btree_toc_entry_t);

	if (old_nkeys == 0) {
		brelse(bp, 0);
		return ENOENT;
	}

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
	uint32_t key_area_start = sizeof(*new_leaf) + table_off + (table_len > toc_size ? table_len - toc_size : 0);
	uint32_t curr_key_off = 0;
	uint32_t curr_val_off = 0;

	uint32_t new_nkeys = old_nkeys - 1;
	new_leaf->btn_nkeys = htole32(new_nkeys);
	new_leaf->btn_table_space_len = htole16(table_len > toc_size ? table_len - toc_size : 0);

	for (uint32_t i = 0; i < new_nkeys; i++) {
		uint32_t src_i = (i < del_idx) ? i : i + 1;
		const void *k_data, *v_data;
		size_t k_sz, v_sz;

		error = apfs_btree_entry(amp, old_leaf, &info, src_i,
		    &k_data, &k_sz, &v_data, &v_sz);
		if (error != 0) {
			brelse(bp, 0);
			brelse(new_bp, 0);
			return error;
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
		if (le32toh(info.bt_key_count) > 0)
			new_info->bt_key_count = htole32(le32toh(info.bt_key_count) - 1);
	}

	leaf_type = (leaf_type & ~OBJECT_TYPE_MASK) |
	    ((leaf_flags & BTNODE_ROOT) ? OBJ_BTREE : OBJ_BTREE_NODE);
	apfs_obj_init(&new_leaf->btn_o, (oid_t)new_leaf_paddr, tx->tx_xid,
	    leaf_type, leaf_subtype);
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
		uint32_t parent_type = le32toh(old_parent->btn_o.o_type);
		uint32_t parent_subtype = le32toh(old_parent->btn_o.o_subtype);

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
			if (le32toh(p_info->bt_key_count) > 0)
				p_info->bt_key_count = htole32(le32toh(p_info->bt_key_count) - 1);
		}

		parent_type = (parent_type & ~OBJECT_TYPE_MASK) |
		    ((p_flags & BTNODE_ROOT) ? OBJ_BTREE : OBJ_BTREE_NODE);
		apfs_obj_init(&new_parent->btn_o, (oid_t)new_parent_paddr,
		    tx->tx_xid, parent_type, parent_subtype);
		apfs_obj_set_cksum(amp, new_parent);

		error = apfs_bwrite(amp, new_parent_paddr, new_bp);
		if (error != 0)
			return error;

		child_paddr = new_parent_paddr;
	}

	/* 4. Update OMap or Root Tree pointer */
	if (omap_oid != 0 && *tree_oid != omap_oid) {
		error = apfs_omap_update(tx, omap_oid, *tree_oid, child_paddr);
		if (error != 0)
			return error;
	} else {
		*tree_oid = (oid_t)child_paddr;
	}

	return 0;
}

int
apfs_btree_remove(struct apfsmount *amp, oid_t *tree_oid, void *key)
{
	apfs_tx_t tx;
	int error;

	error = apfs_tx_begin(amp, &tx);
	if (error != 0)
		return error;

	error = apfs_btree_remove_record(&tx, 0, tree_oid, key, sizeof(j_key_t));
	if (error != 0) {
		apfs_tx_abort(&tx);
		return error;
	}

	return apfs_tx_commit(&tx);
}

int
apfs_btree_insert(struct apfsmount *amp, oid_t *tree_oid, void *key, void *val)
{
	apfs_tx_t tx;
	int error;

	error = apfs_tx_begin(amp, &tx);
	if (error != 0)
		return error;

	error = apfs_btree_insert_record(&tx, 0, tree_oid, key, sizeof(j_key_t), val, sizeof(j_inode_val_t));
	if (error != 0) {
		apfs_tx_abort(&tx);
		return error;
	}

	return apfs_tx_commit(&tx);
}

int
apfs_omap_update(apfs_tx_t *tx, oid_t omap_oid, oid_t oid,
    apfs_paddr_t paddr)
{
	struct apfsmount *amp;
	struct buf *bp, *new_bp;
	uint8_t *omap_copy;
	omap_phys_t *omap;
	omap_key_t key, found_key;
	omap_val_t val, found_val;
	apfs_paddr_t omap_paddr, new_omap_paddr;
	oid_t tree_oid;
	uint32_t object_type, object_subtype;
	int error;

	if (tx == NULL || tx->tx_amp == NULL ||
	    tx->tx_state != APFS_TX_STATE_ACTIVE || omap_oid == 0 ||
	    oid == 0 || paddr <= 0 ||
	    (uint64_t)paddr >= le64toh(tx->tx_amp->am_nx.nx_block_count))
		return EINVAL;

	amp = tx->tx_amp;
	error = apfs_omap_object_paddr(amp, tx, omap_oid, tx->tx_xid,
	    &omap_paddr);
	if (error != 0)
		return error;
	error = apfs_bread(amp, omap_paddr, &bp);
	if (error != 0)
		return error;

	omap = (omap_phys_t *)bp->b_data;
	if (!apfs_checksum_valid(amp, omap) ||
	    le64toh(omap->omap_o.o_oid) != omap_oid ||
	    (le32toh(omap->omap_o.o_type) & OBJECT_TYPE_MASK) != OBJ_OMAP ||
	    le64toh(omap->omap_o.o_xid) > tx->tx_xid) {
		brelse(bp, 0);
		return EINVAL;
	}
	tree_oid = le64toh(omap->omap_tree_oid);
	object_type = le32toh(omap->omap_o.o_type);
	object_subtype = le32toh(omap->omap_o.o_subtype);
	if (tree_oid == 0 ||
	    (object_type & OBJ_STORAGE_MASK) != OBJ_EPHEMERAL) {
		brelse(bp, 0);
		return EOPNOTSUPP;
	}
	omap_copy = kmem_alloc(amp->am_block_size, KM_SLEEP);
	memcpy(omap_copy, bp->b_data, amp->am_block_size);
	brelse(bp, 0);

	key.ok_oid = htole64(oid);
	key.ok_xid = htole64(tx->tx_xid);
	memset(&val, 0, sizeof(val));
	val.ov_size = htole32(amp->am_block_size);
	val.ov_paddr = (apfs_paddr_t)htole64((uint64_t)paddr);

	error = apfs_btree_search(amp, 0, tree_oid, &key, sizeof(key),
	    &found_val, sizeof(found_val), &found_key, sizeof(found_key), NULL);
	if (error == 0 &&
	    le64toh(found_key.ok_oid) == oid &&
	    le64toh(found_key.ok_xid) == tx->tx_xid) {
		error = apfs_btree_remove_record(tx, 0, &tree_oid, &key,
		    sizeof(key));
		if (error != 0)
			goto out;
	} else if (error != 0 && error != ENOENT) {
		goto out;
	}

	error = apfs_btree_insert_record(tx, 0, &tree_oid, &key,
	    sizeof(key), &val, sizeof(val));
	if (error != 0)
		goto out;

	error = apfs_tx_alloc_block(tx, 1, &new_omap_paddr);
	if (error != 0)
		goto out;
	error = apfs_getblk(amp, new_omap_paddr, &new_bp);
	if (error != 0)
		goto out;
	memcpy(new_bp->b_data, omap_copy, amp->am_block_size);
	omap = (omap_phys_t *)new_bp->b_data;
	omap->omap_tree_oid = htole64(tree_oid);
	apfs_obj_init(&omap->omap_o, omap_oid, tx->tx_xid, object_type,
	    object_subtype);
	apfs_obj_set_cksum(amp, omap);
	error = apfs_bwrite(amp, new_omap_paddr, new_bp);
	if (error != 0)
		goto out;

	uint32_t stage_index;
	for (stage_index = 0; stage_index < tx->tx_omap_count; stage_index++) {
		if (tx->tx_omaps[stage_index].os_oid == omap_oid)
			break;
	}
	if (stage_index == tx->tx_omap_count) {
		if (tx->tx_omap_count >= APFS_TX_MAX_OMAPS) {
			error = ENOSPC;
			goto out;
		}
		tx->tx_omap_count++;
	}
	tx->tx_omaps[stage_index].os_oid = omap_oid;
	tx->tx_omaps[stage_index].os_paddr = new_omap_paddr;

	if (omap_oid == le64toh(amp->am_nx.nx_omap_oid)) {
		error = apfs_tx_add_mapping(tx, object_type, object_subtype,
		    amp->am_block_size, 0, omap_oid, new_omap_paddr);
	} else {
		error = apfs_omap_update(tx,
		    le64toh(amp->am_nx.nx_omap_oid), omap_oid,
		    new_omap_paddr);
	}

out:
	kmem_free(omap_copy, amp->am_block_size);
	return error;
}

/* Space Manager: Allocate a new block */
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

/* Transaction Management */

int
apfs_tx_begin(struct apfsmount *amp, apfs_tx_t *tx)
{
	if (amp == NULL || tx == NULL)
		return EINVAL;

	mutex_enter(&amp->am_lock);
	memset(tx, 0, sizeof(*tx));
	tx->tx_amp = amp;
	tx->tx_xid = amp->am_checkpoint_xid + 1;
	tx->tx_state = APFS_TX_STATE_ACTIVE;
	memcpy(&tx->tx_sb_snapshot, &amp->am_sb, sizeof(tx->tx_sb_snapshot));
	tx->tx_resv.rt_tx_id = tx->tx_xid;
	tx->tx_resv.rt_count = 0;
	LIST_INIT(&tx->tx_resv.rt_entries);
	tx->tx_map_count = 0;
	tx->tx_free_count = 0;

	return 0;
}

int
apfs_free_queue_add(apfs_tx_t *tx, apfs_paddr_t paddr, uint64_t count)
{
	if (tx == NULL || paddr == 0 || count == 0)
		return EINVAL;

	if (tx->tx_free_count < APFS_TX_MAX_FREES) {
		tx->tx_frees[tx->tx_free_count].fs_paddr = paddr;
		tx->tx_frees[tx->tx_free_count].fs_count = count;
		tx->tx_free_count++;
		return 0;
	}

	return ENOSPC;
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

	for (uint32_t i = 0; i < tx->tx_map_count; i++) {
		entry = &tx->tx_mappings[i];
		if (le64toh(entry->cpm_fs_oid) == fs_oid &&
		    le64toh(entry->cpm_oid) == oid) {
			entry->cpm_type = htole32(type);
			entry->cpm_subtype = htole32(subtype);
			entry->cpm_size = htole32(size);
			entry->cpm_pad = 0;
			entry->cpm_paddr =
			    (apfs_paddr_t)htole64((uint64_t)paddr);
			return 0;
		}
	}
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
	if (tx == NULL || tx->tx_state == APFS_TX_STATE_INACTIVE ||
	    tx->tx_state == APFS_TX_STATE_ABORTED ||
	    tx->tx_state == APFS_TX_STATE_COMMITTED)
		return;

	if (tx->tx_amp != NULL)
		apfs_resv_abort(tx->tx_amp, &tx->tx_resv);
	if (tx->tx_amp != NULL)
		memcpy(&tx->tx_amp->am_sb, &tx->tx_sb_snapshot,
		    sizeof(tx->tx_sb_snapshot));

	tx->tx_map_count = 0;
	tx->tx_omap_count = 0;
	tx->tx_free_count = 0;
	tx->tx_state = APFS_TX_STATE_ABORTED;
	if (tx->tx_amp != NULL)
		mutex_exit(&tx->tx_amp->am_lock);
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
	if (LIST_EMPTY(&tx->tx_resv.rt_entries) && tx->tx_free_count == 0)
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
		uint32_t     cm_free_count;
		uint8_t     *cm_bitmap;
	} *chunks = NULL;
	uint32_t num_chunks = 0;

	struct cib_mod {
		uint32_t                 cibm_idx;
		apfs_paddr_t             cibm_old_paddr;
		apfs_paddr_t             cibm_new_paddr;
		chunk_info_block_phys_t *cibm_data;
	} *cibs = NULL;
	uint32_t num_cibs = 0;

	chunks = kmem_zalloc(sizeof(*chunks) * APFS_TX_UPDATE_MAX_CHUNKS, KM_SLEEP);
	cibs = kmem_zalloc(sizeof(*cibs) * APFS_TX_UPDATE_MAX_CIBS, KM_SLEEP);

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
					chunks[c_idx].cm_bitmap = (uint8_t *)kmem_zalloc(amp->am_block_size, KM_SLEEP);

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
						cibs[cb_idx].cibm_data = (chunk_info_block_phys_t *)kmem_alloc(amp->am_block_size, KM_SLEEP);
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

		for (uint32_t f = 0; f < tx->tx_free_count; f++) {
			for (uint64_t b = 0; b < tx->tx_frees[f].fs_count; b++) {
				uint64_t p = tx->tx_frees[f].fs_paddr + b;
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
					chunks[c_idx].cm_bitmap = (uint8_t *)kmem_zalloc(amp->am_block_size, KM_SLEEP);

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
						cibs[cb_idx].cibm_data = (chunk_info_block_phys_t *)kmem_alloc(amp->am_block_size, KM_SLEEP);
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

				if ((chunks[c_idx].cm_bitmap[bit >> 3] & (1U << (bit & 7))) != 0) {
					chunks[c_idx].cm_bitmap[bit >> 3] &= ~(1U << (bit & 7));
					chunks[c_idx].cm_free_count++;
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
		apfs_obj_init(cib, (oid_t)cibs[j].cibm_new_paddr, tx->tx_xid,
		    OBJ_SPACEMAN_CIB | OBJ_PHYSICAL, 0);

		for (uint32_t i = 0; i < num_chunks; i++) {
			if (chunks[i].cm_cib_idx == cibs[j].cibm_idx) {
				chunk_info_phys_t *ci = &cib->cib_chunk_info[chunks[i].cm_chunk_in_cib];
				uint32_t old_free = le32toh(ci->ci_free_count);
				uint32_t new_ci_free = old_free + chunks[i].cm_free_count;
				if (new_ci_free >= chunks[i].cm_alloc_count)
					new_ci_free -= chunks[i].cm_alloc_count;
				else
					new_ci_free = 0;
				ci->ci_xid = htole64(tx->tx_xid);
				ci->ci_free_count = htole32(new_ci_free);
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
	new_sm = (spaceman_phys_t *)kmem_alloc(amp->am_block_size, KM_SLEEP);
	memcpy(new_sm, sm, amp->am_block_size);
	apfs_obj_init(new_sm, le64toh(amp->am_nx.nx_spaceman_oid), tx->tx_xid,
	    OBJ_SPACEMAN | OBJ_EPHEMERAL, 0);

	uint64_t total_freed = 0;
	for (uint32_t i = 0; i < num_chunks; i++)
		total_freed += chunks[i].cm_free_count;

	uint64_t old_sm_free = le64toh(new_sm->sm_dev[0].sm_free_count);
	uint64_t total_allocated = tx->tx_resv.rt_count;
	uint64_t new_sm_free_val = (old_sm_free + total_freed >= total_allocated) ?
	    (old_sm_free + total_freed - total_allocated) : 0;
	new_sm->sm_dev[0].sm_free_count = htole64(new_sm_free_val);

	/* Rotate free queues */
	new_sm->sm_fq[2] = new_sm->sm_fq[1];
	new_sm->sm_fq[1] = new_sm->sm_fq[0];
	if (tx->tx_free_count > 0) {
		new_sm->sm_fq[0].sfq_count = htole64(total_freed);
		new_sm->sm_fq[0].sfq_tree_oid = htole64(tx->tx_frees[0].fs_paddr);
		new_sm->sm_fq[0].sfq_oldest_xid = htole64(tx->tx_xid);
	} else {
		memset(&new_sm->sm_fq[0], 0, sizeof(new_sm->sm_fq[0]));
	}

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
	error = apfs_tx_add_mapping(tx, OBJ_SPACEMAN | OBJ_EPHEMERAL, 0,
	    amp->am_block_size, 0, le64toh(amp->am_nx.nx_spaceman_oid), new_sm_paddr);

out:
	if (smbp != NULL)
		brelse(smbp, 0);
	if (new_sm != NULL)
		kmem_free(new_sm, amp->am_block_size);
	if (chunks != NULL) {
		for (uint32_t i = 0; i < num_chunks; i++) {
			if (chunks[i].cm_bitmap != NULL)
				kmem_free(chunks[i].cm_bitmap, amp->am_block_size);
		}
		kmem_free(chunks, sizeof(*chunks) * APFS_TX_UPDATE_MAX_CHUNKS);
	}
	if (cibs != NULL) {
		for (uint32_t j = 0; j < num_cibs; j++) {
			if (cibs[j].cibm_data != NULL)
				kmem_free(cibs[j].cibm_data, amp->am_block_size);
		}
		kmem_free(cibs, sizeof(*cibs) * APFS_TX_UPDATE_MAX_CIBS);
	}

	return error;
}

static int
apfs_tx_stage_superblock(apfs_tx_t *tx)
{
	struct apfsmount *amp = tx->tx_amp;
	struct buf *bp;
	apfs_superblock_t new_sb;
	apfs_superblock_t *sb;
	apfs_paddr_t paddr;
	oid_t fs_oid, omap_oid;
	uint32_t type, subtype;
	int error;

	if (memcmp(&tx->tx_sb_snapshot, &amp->am_sb,
	    sizeof(amp->am_sb)) == 0)
		return 0;

	fs_oid = le64toh(amp->am_sb.apfs_o.o_oid);
	omap_oid = le64toh(amp->am_sb.apfs_omap_oid);
	type = le32toh(amp->am_sb.apfs_o.o_type);
	subtype = le32toh(amp->am_sb.apfs_o.o_subtype);
	if (fs_oid == 0 || omap_oid == 0 ||
	    (type & OBJECT_TYPE_MASK) != OBJ_FS ||
	    (type & OBJ_STORAGE_MASK) != OBJ_EPHEMERAL)
		return EOPNOTSUPP;

	error = apfs_tx_alloc_block(tx, 1, &paddr);
	if (error != 0)
		return error;
	error = apfs_getblk(amp, paddr, &bp);
	if (error != 0)
		return error;

	memcpy(&new_sb, &amp->am_sb, sizeof(new_sb));
	sb = &new_sb;
	apfs_obj_init(&sb->apfs_o, fs_oid, tx->tx_xid, type, subtype);
	memset(bp->b_data, 0, amp->am_block_size);
	memcpy(bp->b_data, sb, sizeof(*sb));
	sb = (apfs_superblock_t *)bp->b_data;
	apfs_obj_set_cksum(amp, sb);
	memcpy(new_sb.apfs_o.o_cksum, sb->apfs_o.o_cksum,
	    sizeof(new_sb.apfs_o.o_cksum));
	error = apfs_bwrite(amp, paddr, bp);
	if (error != 0)
		return error;

	memcpy(&amp->am_sb, &new_sb, sizeof(amp->am_sb));
	return apfs_omap_update(tx, omap_oid, fs_oid, paddr);
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

	if (desc_blocks == 0 || desc_base == 0) {
		apfs_tx_abort(tx);
		return EINVAL;
	}

	error = apfs_tx_stage_superblock(tx);
	if (error != 0) {
		apfs_tx_abort(tx);
		return error;
	}

	/* Phase 1: Update Space Manager, CIBs, and Bitmaps if any allocations made */
	error = apfs_spaceman_tx_update(tx);
	if (error != 0) {
		apfs_tx_abort(tx);
		return error;
	}

	capacity = (amp->am_block_size - sizeof(checkpoint_map_phys_t)) /
	    sizeof(checkpoint_mapping_t);
	if (capacity == 0) {
		apfs_tx_abort(tx);
		return EINVAL;
	}

	map_count = tx->tx_map_count;
	num_map_blocks = (map_count == 0) ? 1 : (map_count + capacity - 1) / capacity;
	new_desc_len = num_map_blocks + 1;

	if (new_desc_len > desc_blocks) {
		apfs_tx_abort(tx);
		return ENOSPC;
	}

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
				kmem_free(pe, sizeof(*pe));
				break;
			}
			pe = ptmp;
		}
		LIST_REMOVE(re, re_link);
		kmem_free(re, sizeof(*re));
		re = tmp;
	}
	tx->tx_resv.rt_count = 0;
	mutex_exit(&amp->am_resv_pool.rp_lock);
	tx->tx_state = APFS_TX_STATE_COMMITTED;
	mutex_exit(&amp->am_lock);

	return 0;
}

int
apfs_create_file(struct apfsmount *amp, oid_t parent_oid, const char *name,
    mode_t mode, uid_t uid, gid_t gid, oid_t *new_oidp)
{
	apfs_tx_t tx;
	oid_t new_ino_oid;
	uint32_t name_len = strlen(name);
	uint64_t incompat_features = le64toh(amp->am_sb.apfs_incompatible_features);
	uint32_t name_hash = 0;
	struct timespec ts;
	uint64_t now_ns;
	int error;

	error = apfs_name_hash(name, name_len,
	    (incompat_features & APFS_INCOMPAT_CASE_INSENSITIVE) != 0,
	    (incompat_features & APFS_INCOMPAT_NORMALIZATION_INSENSITIVE) != 0,
	    &name_hash);
	if (error != 0)
		return error;

	nanotime(&ts);
	now_ns = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;

	error = apfs_tx_begin(amp, &tx);
	if (error != 0)
		return error;

	new_ino_oid = le64toh(amp->am_sb.apfs_next_obj_id);
	amp->am_sb.apfs_next_obj_id = htole64(new_ino_oid + 1);

	/* 1. Inode Record */
	j_key_t ino_key;
	ino_key.obj_id_and_type = htole64((new_ino_oid & OBJ_ID_MASK) |
	    ((uint64_t)APFS_TYPE_INODE << OBJ_TYPE_SHIFT));

	j_inode_val_t ino_val;
	memset(&ino_val, 0, sizeof(ino_val));
	ino_val.parent_id = htole64(parent_oid);
	ino_val.private_id = htole64(new_ino_oid);
	ino_val.create_time = htole64(now_ns);
	ino_val.mod_time = htole64(now_ns);
	ino_val.change_time = htole64(now_ns);
	ino_val.access_time = htole64(now_ns);
	ino_val.internal_flags = htole64(0);
	ino_val.nlink = htole32(1);
	ino_val.bsd_flags = 0;
	ino_val.owner = htole32(uid);
	ino_val.group = htole32(gid);
	ino_val.mode = htole16((mode & 07777) | S_IFREG);
	ino_val.uncompressed_size = 0;

	oid_t root_tree_oid = le64toh(amp->am_sb.apfs_root_tree_oid);
	oid_t omap_oid = le64toh(amp->am_sb.apfs_omap_oid);

	error = apfs_btree_insert_record(&tx, omap_oid, &root_tree_oid,
	    &ino_key, sizeof(ino_key), &ino_val, sizeof(ino_val));
	if (error != 0) {
		apfs_tx_abort(&tx);
		return error;
	}

	/* 2. Directory Entry Record */
	size_t drec_key_size = sizeof(j_drec_key_t) + name_len + 1;
	j_drec_key_t *drec_key = kmem_zalloc(drec_key_size, KM_SLEEP);
	drec_key->obj_id_and_type = htole64((parent_oid & OBJ_ID_MASK) |
	    ((uint64_t)APFS_TYPE_DIR_REC << OBJ_TYPE_SHIFT));
	drec_key->name_len_and_hash = htole32((name_hash << DREC_HASH_SHIFT) |
	    (name_len & DREC_NLEN_MASK));
	memcpy(drec_key->name, name, name_len);
	drec_key->name[name_len] = '\0';

	j_drec_val_t drec_val;
	memset(&drec_val, 0, sizeof(drec_val));
	drec_val.file_id = htole64(new_ino_oid);
	drec_val.date_added = htole64(now_ns);
	drec_val.flags = htole16(DT_REG);

	error = apfs_btree_insert_record(&tx, omap_oid, &root_tree_oid,
	    drec_key, drec_key_size, &drec_val, sizeof(drec_val));
	kmem_free(drec_key, drec_key_size);
	if (error != 0) {
		apfs_tx_abort(&tx);
		return error;
	}

	/* Update superblock */
	uint64_t num_files = le64toh(amp->am_sb.apfs_num_files);
	amp->am_sb.apfs_num_files = htole64(num_files + 1);
	amp->am_sb.apfs_root_tree_oid = htole64(root_tree_oid);

	error = apfs_tx_commit(&tx);
	if (error != 0)
		return error;

	if (new_oidp != NULL)
		*new_oidp = new_ino_oid;

	return 0;
}

int
apfs_update_inode(apfs_tx_t *tx, struct apfsnode *apnode)
{
	struct apfsmount *amp;
	oid_t root_tree_oid, omap_oid;
	j_key_t ino_key;
	uint8_t *ino_buf;
	j_inode_val_t *ino_val;
	size_t ino_len = 0, write_len;
	int error;

	if (tx == NULL || tx->tx_amp == NULL || apnode == NULL)
		return EINVAL;

	amp = tx->tx_amp;
	root_tree_oid = le64toh(amp->am_sb.apfs_root_tree_oid);
	omap_oid = le64toh(amp->am_sb.apfs_omap_oid);

	ino_key.obj_id_and_type = htole64((apnode->a_oid & OBJ_ID_MASK) |
	    ((uint64_t)APFS_TYPE_INODE << OBJ_TYPE_SHIFT));

	ino_buf = kmem_alloc(amp->am_block_size, KM_SLEEP);
	error = apfs_btree_search(amp, omap_oid, root_tree_oid,
	    &ino_key, sizeof(ino_key), ino_buf, amp->am_block_size, NULL, 0, &ino_len);

	if (error == 0 && ino_len >= sizeof(j_inode_val_t)) {
		ino_val = (j_inode_val_t *)ino_buf;
		write_len = ino_len;
	} else {
		memset(ino_buf, 0, sizeof(j_inode_val_t));
		ino_val = (j_inode_val_t *)ino_buf;
		write_len = sizeof(j_inode_val_t);
	}

	ino_val->parent_id = htole64(apnode->a_ino.parent_id);
	ino_val->private_id = htole64(apnode->a_ino.private_id);
	ino_val->create_time = htole64(apnode->a_ino.create_time);
	ino_val->mod_time = htole64(apnode->a_ino.mod_time);
	ino_val->change_time = htole64(apnode->a_ino.change_time);
	ino_val->access_time = htole64(apnode->a_ino.access_time);
	ino_val->internal_flags = htole64(apnode->a_ino.internal_flags);
	ino_val->nlink = htole32(apnode->a_ino.nlink);
	ino_val->bsd_flags = htole32(apnode->a_ino.bsd_flags);
	ino_val->owner = htole32(apnode->a_ino.owner);
	ino_val->group = htole32(apnode->a_ino.group);
	ino_val->mode = htole16(apnode->a_ino.mode);
	ino_val->uncompressed_size = htole64(apnode->a_ino.uncompressed_size);

	/* If dstream xfield exists, update dstream.size */
	if (write_len > sizeof(j_inode_val_t)) {
		uint8_t *xfields = ino_buf + sizeof(j_inode_val_t);
		size_t xfields_len = write_len - sizeof(j_inode_val_t);
		if (xfields_len >= sizeof(j_xfield_header_t)) {
			j_xfield_header_t *hdr = (j_xfield_header_t *)xfields;
			uint16_t num_xf = le16toh(hdr->num_xfields);
			uint8_t *cur = xfields + sizeof(j_xfield_header_t);
			uint8_t *val_ptr = cur + num_xf * sizeof(j_xfield_t);
			for (uint16_t x = 0; x < num_xf; x++) {
				if (cur + sizeof(j_xfield_t) > val_ptr)
					break;
				j_xfield_t *xf = (j_xfield_t *)cur;
				uint16_t xf_type = le16toh(xf->type) & APFS_XFIELD_TYPE_MASK;
				uint16_t xf_size = le16toh(xf->size);
				if ((uint16_t)(val_ptr - xfields) + xf_size > xfields_len)
					break;
				if (xf_type == APFS_XFIELD_TYPE_DSTREAM && xf_size >= sizeof(j_dstream_t)) {
					j_dstream_t *ds = (j_dstream_t *)val_ptr;
					ds->size = htole64(apnode->a_ino.uncompressed_size);
					ds->alloced_size = htole64((apnode->a_ino.uncompressed_size +
					    amp->am_block_size - 1) & ~((uint64_t)amp->am_block_size - 1));
				}
				cur += sizeof(j_xfield_t);
				val_ptr += (xf_size + 7) & ~7;
			}
		}
	}

	error = apfs_btree_insert_record(tx, omap_oid, &root_tree_oid,
	    &ino_key, sizeof(ino_key), ino_val, write_len);
	kmem_free(ino_buf, amp->am_block_size);

	if (error == 0) {
		amp->am_sb.apfs_root_tree_oid = htole64(root_tree_oid);
	}
	return error;
}

int
apfs_write_file_extent(struct apfsmount *amp, oid_t ino_oid, uint64_t file_offset,
    uint64_t length, apfs_paddr_t paddr)
{
	apfs_tx_t tx;
	oid_t root_tree_oid, omap_oid;
	j_extent_key_t ext_key;
	j_phys_ext_val_t ext_val;
	int error;

	error = apfs_tx_begin(amp, &tx);
	if (error != 0)
		return error;

	root_tree_oid = le64toh(amp->am_sb.apfs_root_tree_oid);
	omap_oid = le64toh(amp->am_sb.apfs_omap_oid);

	ext_key.obj_id_and_type = htole64((ino_oid & OBJ_ID_MASK) |
	    ((uint64_t)APFS_TYPE_EXTENT << OBJ_TYPE_SHIFT));
	ext_key.logical_addr = htole64(file_offset);

	ext_val.len_and_flags = htole64(length & EXTENT_LEN_MASK);
	ext_val.phys_addr = htole64((uint64_t)paddr);

	error = apfs_btree_insert_record(&tx, omap_oid, &root_tree_oid,
	    &ext_key, sizeof(ext_key), &ext_val, sizeof(ext_val));
	if (error != 0) {
		apfs_tx_abort(&tx);
		return error;
	}

	amp->am_sb.apfs_root_tree_oid = htole64(root_tree_oid);
	return apfs_tx_commit(&tx);
}

struct apfs_extent_list_entry {
	j_extent_key_t key;
	j_phys_ext_val_t val;
	SLIST_ENTRY(apfs_extent_list_entry) link;
};

static int
apfs_collect_extents_cb(void *arg, const void *k, size_t klen, const void *v, size_t vlen)
{
	SLIST_HEAD(, apfs_extent_list_entry) *head = arg;
	if (klen >= sizeof(j_extent_key_t) && vlen >= sizeof(j_phys_ext_val_t)) {
		struct apfs_extent_list_entry *entry = kmem_zalloc(sizeof(*entry), KM_SLEEP);
		memcpy(&entry->key, k, sizeof(entry->key));
		memcpy(&entry->val, v, sizeof(entry->val));
		SLIST_INSERT_HEAD(head, entry, link);
	}
	return 0;
}

static int
apfs_remove_file_extents(apfs_tx_t *tx, oid_t ino_oid, oid_t *root_tree_oid)
{
	struct apfsmount *amp = tx->tx_amp;
	oid_t omap_oid = le64toh(amp->am_sb.apfs_omap_oid);
	SLIST_HEAD(, apfs_extent_list_entry) head = SLIST_HEAD_INITIALIZER(head);
	j_extent_key_t start_key;
	memset(&start_key, 0, sizeof(start_key));
	start_key.obj_id_and_type = htole64((ino_oid & OBJ_ID_MASK) |
	    ((uint64_t)APFS_TYPE_EXTENT << OBJ_TYPE_SHIFT));

	apfs_btree_iterate(amp, omap_oid, *root_tree_oid, &start_key, sizeof(start_key),
	    apfs_collect_extents_cb, &head);

	struct apfs_extent_list_entry *entry;
	while (!SLIST_EMPTY(&head)) {
		entry = SLIST_FIRST(&head);
		SLIST_REMOVE_HEAD(&head, link);

		uint64_t kw = le64toh(entry->key.obj_id_and_type);
		if ((kw & OBJ_ID_MASK) == (ino_oid & OBJ_ID_MASK) &&
		    ((kw & OBJ_TYPE_MASK) >> OBJ_TYPE_SHIFT) == APFS_TYPE_EXTENT) {
			uint64_t phys_block = le64toh(entry->val.phys_addr);
			uint64_t len = le64toh(entry->val.len_and_flags) & EXTENT_LEN_MASK;
			uint64_t count = (len + amp->am_block_size - 1) / amp->am_block_size;

			apfs_free_queue_add(tx, (apfs_paddr_t)phys_block, count);
			apfs_btree_remove_record(tx, omap_oid, root_tree_oid,
			    &entry->key, sizeof(entry->key));
		}
		kmem_free(entry, sizeof(*entry));
	}
	return 0;
}

static int
apfs_truncate_file_extents(apfs_tx_t *tx, oid_t ino_oid, uint64_t new_size, oid_t *root_tree_oid)
{
	struct apfsmount *amp = tx->tx_amp;
	oid_t omap_oid = le64toh(amp->am_sb.apfs_omap_oid);
	SLIST_HEAD(, apfs_extent_list_entry) head = SLIST_HEAD_INITIALIZER(head);
	j_extent_key_t start_key;
	memset(&start_key, 0, sizeof(start_key));
	start_key.obj_id_and_type = htole64((ino_oid & OBJ_ID_MASK) |
	    ((uint64_t)APFS_TYPE_EXTENT << OBJ_TYPE_SHIFT));

	apfs_btree_iterate(amp, omap_oid, *root_tree_oid, &start_key, sizeof(start_key),
	    apfs_collect_extents_cb, &head);

	struct apfs_extent_list_entry *entry;
	while (!SLIST_EMPTY(&head)) {
		entry = SLIST_FIRST(&head);
		SLIST_REMOVE_HEAD(&head, link);

		uint64_t kw = le64toh(entry->key.obj_id_and_type);
		if ((kw & OBJ_ID_MASK) == (ino_oid & OBJ_ID_MASK) &&
		    ((kw & OBJ_TYPE_MASK) >> OBJ_TYPE_SHIFT) == APFS_TYPE_EXTENT) {
			uint64_t logical_addr = le64toh(entry->key.logical_addr);
			uint64_t phys_block = le64toh(entry->val.phys_addr);
			uint64_t len = le64toh(entry->val.len_and_flags) & EXTENT_LEN_MASK;

			if (logical_addr >= new_size) {
				uint64_t count = (len + amp->am_block_size - 1) / amp->am_block_size;
				apfs_free_queue_add(tx, (apfs_paddr_t)phys_block, count);
				apfs_btree_remove_record(tx, omap_oid, root_tree_oid,
				    &entry->key, sizeof(entry->key));
			} else if (logical_addr + len > new_size) {
				uint64_t keep_len = new_size - logical_addr;
				uint64_t keep_blocks = (keep_len + amp->am_block_size - 1) / amp->am_block_size;
				uint64_t total_blocks = (len + amp->am_block_size - 1) / amp->am_block_size;
				if (total_blocks > keep_blocks) {
					apfs_free_queue_add(tx, (apfs_paddr_t)(phys_block + keep_blocks),
					    total_blocks - keep_blocks);
				}
				entry->val.len_and_flags = htole64(keep_len & EXTENT_LEN_MASK);
				apfs_btree_insert_record(tx, omap_oid, root_tree_oid,
				    &entry->key, sizeof(entry->key), &entry->val, sizeof(entry->val));
			}
		}
		kmem_free(entry, sizeof(*entry));
	}
	return 0;
}

int
apfs_create_dir(struct apfsmount *amp, oid_t parent_oid, const char *name,
    mode_t mode, uid_t uid, gid_t gid, oid_t *new_oidp)
{
	apfs_tx_t tx;
	oid_t new_ino_oid;
	uint32_t name_len = strlen(name);
	uint64_t incompat_features = le64toh(amp->am_sb.apfs_incompatible_features);
	uint32_t name_hash = 0;
	struct timespec ts;
	uint64_t now_ns;
	int error;

	error = apfs_name_hash(name, name_len,
	    (incompat_features & APFS_INCOMPAT_CASE_INSENSITIVE) != 0,
	    (incompat_features & APFS_INCOMPAT_NORMALIZATION_INSENSITIVE) != 0,
	    &name_hash);
	if (error != 0)
		return error;

	nanotime(&ts);
	now_ns = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;

	error = apfs_tx_begin(amp, &tx);
	if (error != 0)
		return error;

	new_ino_oid = le64toh(amp->am_sb.apfs_next_obj_id);
	amp->am_sb.apfs_next_obj_id = htole64(new_ino_oid + 1);

	/* 1. Inode Record */
	j_key_t ino_key;
	ino_key.obj_id_and_type = htole64((new_ino_oid & OBJ_ID_MASK) |
	    ((uint64_t)APFS_TYPE_INODE << OBJ_TYPE_SHIFT));

	j_inode_val_t ino_val;
	memset(&ino_val, 0, sizeof(ino_val));
	ino_val.parent_id = htole64(parent_oid);
	ino_val.private_id = htole64(new_ino_oid);
	ino_val.create_time = htole64(now_ns);
	ino_val.mod_time = htole64(now_ns);
	ino_val.change_time = htole64(now_ns);
	ino_val.access_time = htole64(now_ns);
	ino_val.internal_flags = htole64(0);
	ino_val.nchildren = htole32(2);
	ino_val.bsd_flags = 0;
	ino_val.owner = htole32(uid);
	ino_val.group = htole32(gid);
	ino_val.mode = htole16((mode & 07777) | S_IFDIR);
	ino_val.uncompressed_size = 0;

	oid_t root_tree_oid = le64toh(amp->am_sb.apfs_root_tree_oid);
	oid_t omap_oid = le64toh(amp->am_sb.apfs_omap_oid);

	error = apfs_btree_insert_record(&tx, omap_oid, &root_tree_oid,
	    &ino_key, sizeof(ino_key), &ino_val, sizeof(ino_val));
	if (error != 0) {
		apfs_tx_abort(&tx);
		return error;
	}

	/* 2. Directory Entry Record */
	size_t drec_key_size = sizeof(j_drec_key_t) + name_len + 1;
	j_drec_key_t *drec_key = kmem_zalloc(drec_key_size, KM_SLEEP);
	drec_key->obj_id_and_type = htole64((parent_oid & OBJ_ID_MASK) |
	    ((uint64_t)APFS_TYPE_DIR_REC << OBJ_TYPE_SHIFT));
	drec_key->name_len_and_hash = htole32((name_hash << DREC_HASH_SHIFT) |
	    (name_len & DREC_NLEN_MASK));
	memcpy(drec_key->name, name, name_len);
	drec_key->name[name_len] = '\0';

	j_drec_val_t drec_val;
	memset(&drec_val, 0, sizeof(drec_val));
	drec_val.file_id = htole64(new_ino_oid);
	drec_val.date_added = htole64(now_ns);
	drec_val.flags = htole16(DT_DIR);

	error = apfs_btree_insert_record(&tx, omap_oid, &root_tree_oid,
	    drec_key, drec_key_size, &drec_val, sizeof(drec_val));
	kmem_free(drec_key, drec_key_size);
	if (error != 0) {
		apfs_tx_abort(&tx);
		return error;
	}

	/* Update superblock */
	uint64_t num_folders = le64toh(amp->am_sb.apfs_num_directories);
	amp->am_sb.apfs_num_directories = htole64(num_folders + 1);
	amp->am_sb.apfs_root_tree_oid = htole64(root_tree_oid);

	error = apfs_tx_commit(&tx);
	if (error != 0)
		return error;

	if (new_oidp != NULL)
		*new_oidp = new_ino_oid;

	return 0;
}

struct apfs_empty_check_ctx {
	oid_t dir_oid;
	bool has_entries;
};

static int
apfs_empty_check_cb(void *arg, const void *k, size_t klen, const void *v, size_t vlen)
{
	struct apfs_empty_check_ctx *ctx = arg;
	if (klen >= sizeof(uint64_t)) {
		uint64_t kw = le64toh(*(const uint64_t *)k);
		if ((kw & OBJ_ID_MASK) == ctx->dir_oid &&
		    ((kw & OBJ_TYPE_MASK) >> OBJ_TYPE_SHIFT) == APFS_TYPE_DIR_REC) {
			ctx->has_entries = true;
			return EEXIST;
		}
	}
	return 0;
}

int
apfs_remove_dir(struct apfsmount *amp, oid_t parent_oid, const char *name,
    oid_t target_oid)
{
	apfs_tx_t tx;
	oid_t root_tree_oid, omap_oid;
	uint32_t name_len = strlen(name);
	uint64_t incompat_features = le64toh(amp->am_sb.apfs_incompatible_features);
	uint32_t name_hash = 0;
	int error;

	if (amp == NULL)
		return EINVAL;

	error = apfs_name_hash(name, name_len,
	    (incompat_features & APFS_INCOMPAT_CASE_INSENSITIVE) != 0,
	    (incompat_features & APFS_INCOMPAT_NORMALIZATION_INSENSITIVE) != 0,
	    &name_hash);
	if (error != 0)
		return error;

	root_tree_oid = le64toh(amp->am_sb.apfs_root_tree_oid);
	omap_oid = le64toh(amp->am_sb.apfs_omap_oid);

	/* Check emptiness */
	struct apfs_empty_check_ctx empty_ctx = { target_oid, false };
	j_drec_key_t start_key;
	memset(&start_key, 0, sizeof(start_key));
	start_key.obj_id_and_type = htole64((target_oid & OBJ_ID_MASK) |
	    ((uint64_t)APFS_TYPE_DIR_REC << OBJ_TYPE_SHIFT));

	apfs_btree_iterate(amp, omap_oid, root_tree_oid, &start_key, sizeof(start_key),
	    apfs_empty_check_cb, &empty_ctx);
	if (empty_ctx.has_entries)
		return ENOTEMPTY;

	error = apfs_tx_begin(amp, &tx);
	if (error != 0)
		return error;

	/* 1. Remove directory entry in parent */
	size_t drec_key_size = sizeof(j_drec_key_t) + name_len + 1;
	j_drec_key_t *drec_key = kmem_zalloc(drec_key_size, KM_SLEEP);
	drec_key->obj_id_and_type = htole64((parent_oid & OBJ_ID_MASK) |
	    ((uint64_t)APFS_TYPE_DIR_REC << OBJ_TYPE_SHIFT));
	drec_key->name_len_and_hash = htole32((name_hash << DREC_HASH_SHIFT) |
	    (name_len & DREC_NLEN_MASK));
	memcpy(drec_key->name, name, name_len);
	drec_key->name[name_len] = '\0';

	error = apfs_btree_remove_record(&tx, omap_oid, &root_tree_oid,
	    drec_key, drec_key_size);
	kmem_free(drec_key, drec_key_size);
	if (error != 0) {
		apfs_tx_abort(&tx);
		return error;
	}

	/* 2. Remove directory inode record */
	j_key_t ino_key;
	ino_key.obj_id_and_type = htole64((target_oid & OBJ_ID_MASK) |
	    ((uint64_t)APFS_TYPE_INODE << OBJ_TYPE_SHIFT));
	error = apfs_btree_remove_record(&tx, omap_oid, &root_tree_oid,
	    &ino_key, sizeof(ino_key));
	if (error != 0 && error != ENOENT) {
		apfs_tx_abort(&tx);
		return error;
	}

	uint64_t num_folders = le64toh(amp->am_sb.apfs_num_directories);
	if (num_folders > 0)
		amp->am_sb.apfs_num_directories = htole64(num_folders - 1);
	amp->am_sb.apfs_root_tree_oid = htole64(root_tree_oid);

	return apfs_tx_commit(&tx);
}

int
apfs_remove_file(struct apfsmount *amp, oid_t parent_oid, const char *name,
    oid_t target_oid)
{
	apfs_tx_t tx;
	oid_t root_tree_oid, omap_oid;
	uint32_t name_len = strlen(name);
	uint64_t incompat_features = le64toh(amp->am_sb.apfs_incompatible_features);
	uint32_t name_hash = 0;
	int error;

	if (amp == NULL)
		return EINVAL;

	error = apfs_name_hash(name, name_len,
	    (incompat_features & APFS_INCOMPAT_CASE_INSENSITIVE) != 0,
	    (incompat_features & APFS_INCOMPAT_NORMALIZATION_INSENSITIVE) != 0,
	    &name_hash);
	if (error != 0)
		return error;

	error = apfs_tx_begin(amp, &tx);
	if (error != 0)
		return error;

	root_tree_oid = le64toh(amp->am_sb.apfs_root_tree_oid);
	omap_oid = le64toh(amp->am_sb.apfs_omap_oid);

	/* 1. Remove parent directory entry */
	size_t drec_key_size = sizeof(j_drec_key_t) + name_len + 1;
	j_drec_key_t *drec_key = kmem_zalloc(drec_key_size, KM_SLEEP);
	drec_key->obj_id_and_type = htole64((parent_oid & OBJ_ID_MASK) |
	    ((uint64_t)APFS_TYPE_DIR_REC << OBJ_TYPE_SHIFT));
	drec_key->name_len_and_hash = htole32((name_hash << DREC_HASH_SHIFT) |
	    (name_len & DREC_NLEN_MASK));
	memcpy(drec_key->name, name, name_len);
	drec_key->name[name_len] = '\0';

	error = apfs_btree_remove_record(&tx, omap_oid, &root_tree_oid,
	    drec_key, drec_key_size);
	kmem_free(drec_key, drec_key_size);
	if (error != 0) {
		apfs_tx_abort(&tx);
		return error;
	}

	/* 2. Look up Inode */
	j_key_t ino_key;
	ino_key.obj_id_and_type = htole64((target_oid & OBJ_ID_MASK) |
	    ((uint64_t)APFS_TYPE_INODE << OBJ_TYPE_SHIFT));

	uint8_t *ino_buf = kmem_alloc(amp->am_block_size, KM_SLEEP);
	size_t ino_len = 0;
	error = apfs_btree_search(amp, omap_oid, root_tree_oid,
	    &ino_key, sizeof(ino_key), ino_buf, amp->am_block_size, NULL, 0, &ino_len);
	if (error == 0 && ino_len >= sizeof(j_inode_val_t)) {
		j_inode_val_t *ino_val = (j_inode_val_t *)ino_buf;
		uint32_t nlink = le32toh(ino_val->nlink);
		if (nlink <= 1) {
			apfs_btree_remove_record(&tx, omap_oid, &root_tree_oid,
			    &ino_key, sizeof(ino_key));
			apfs_remove_file_extents(&tx, target_oid, &root_tree_oid);
			uint64_t num_files = le64toh(amp->am_sb.apfs_num_files);
			if (num_files > 0)
				amp->am_sb.apfs_num_files = htole64(num_files - 1);
		} else {
			ino_val->nlink = htole32(nlink - 1);
			apfs_btree_insert_record(&tx, omap_oid, &root_tree_oid,
			    &ino_key, sizeof(ino_key), ino_val, ino_len);
		}
	}
	kmem_free(ino_buf, amp->am_block_size);

	amp->am_sb.apfs_root_tree_oid = htole64(root_tree_oid);
	return apfs_tx_commit(&tx);
}

int
apfs_truncate_file(struct apfsmount *amp, struct apfsnode *apnode, uint64_t new_size)
{
	apfs_tx_t tx;
	oid_t root_tree_oid;
	int error;

	if (amp == NULL || apnode == NULL)
		return EINVAL;

	error = apfs_tx_begin(amp, &tx);
	if (error != 0)
		return error;

	root_tree_oid = le64toh(amp->am_sb.apfs_root_tree_oid);

	if (new_size < apnode->a_ino.uncompressed_size) {
		apfs_truncate_file_extents(&tx, apnode->a_oid, new_size, &root_tree_oid);
	}

	apnode->a_ino.uncompressed_size = new_size;
	struct timespec ts;
	nanotime(&ts);
	uint64_t now_ns = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
	apnode->a_ino.mod_time = now_ns;
	apnode->a_ino.change_time = now_ns;

	error = apfs_update_inode(&tx, apnode);
	if (error != 0) {
		apfs_tx_abort(&tx);
		return error;
	}

	return apfs_tx_commit(&tx);
}

int
apfs_create_symlink(struct apfsmount *amp, oid_t parent_oid, const char *name,
    const char *target, uid_t uid, gid_t gid, oid_t *new_oidp)
{
	apfs_tx_t tx;
	oid_t new_ino_oid;
	uint32_t name_len = strlen(name);
	uint32_t target_len = strlen(target);
	uint64_t incompat_features = le64toh(amp->am_sb.apfs_incompatible_features);
	uint32_t name_hash = 0;
	struct timespec ts;
	uint64_t now_ns;
	apfs_paddr_t target_paddr;
	struct buf *bp;
	int error;

	error = apfs_name_hash(name, name_len,
	    (incompat_features & APFS_INCOMPAT_CASE_INSENSITIVE) != 0,
	    (incompat_features & APFS_INCOMPAT_NORMALIZATION_INSENSITIVE) != 0,
	    &name_hash);
	if (error != 0)
		return error;

	nanotime(&ts);
	now_ns = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;

	error = apfs_tx_begin(amp, &tx);
	if (error != 0)
		return error;

	new_ino_oid = le64toh(amp->am_sb.apfs_next_obj_id);
	amp->am_sb.apfs_next_obj_id = htole64(new_ino_oid + 1);

	/* 1. Allocate block and write target path string */
	error = apfs_tx_alloc_block(&tx, 1, &target_paddr);
	if (error != 0) {
		apfs_tx_abort(&tx);
		return error;
	}

	error = apfs_getblk(amp, target_paddr, &bp);
	if (error != 0) {
		apfs_tx_abort(&tx);
		return error;
	}

	memset(bp->b_data, 0, amp->am_block_size);
	memcpy(bp->b_data, target, target_len);
	error = apfs_bwrite(amp, target_paddr, bp);
	if (error != 0) {
		apfs_tx_abort(&tx);
		return error;
	}

	/* 2. Inode Record */
	j_key_t ino_key;
	ino_key.obj_id_and_type = htole64((new_ino_oid & OBJ_ID_MASK) |
	    ((uint64_t)APFS_TYPE_INODE << OBJ_TYPE_SHIFT));

	j_inode_val_t ino_val;
	memset(&ino_val, 0, sizeof(ino_val));
	ino_val.parent_id = htole64(parent_oid);
	ino_val.private_id = htole64(new_ino_oid);
	ino_val.create_time = htole64(now_ns);
	ino_val.mod_time = htole64(now_ns);
	ino_val.change_time = htole64(now_ns);
	ino_val.access_time = htole64(now_ns);
	ino_val.nlink = htole32(1);
	ino_val.owner = htole32(uid);
	ino_val.group = htole32(gid);
	ino_val.mode = htole16(0777 | S_IFLNK);
	ino_val.uncompressed_size = htole64(target_len);

	oid_t root_tree_oid = le64toh(amp->am_sb.apfs_root_tree_oid);
	oid_t omap_oid = le64toh(amp->am_sb.apfs_omap_oid);

	error = apfs_btree_insert_record(&tx, omap_oid, &root_tree_oid,
	    &ino_key, sizeof(ino_key), &ino_val, sizeof(ino_val));
	if (error != 0) {
		apfs_tx_abort(&tx);
		return error;
	}

	/* 3. Extent Record for Target Data */
	j_extent_key_t ext_key;
	ext_key.obj_id_and_type = htole64((new_ino_oid & OBJ_ID_MASK) |
	    ((uint64_t)APFS_TYPE_EXTENT << OBJ_TYPE_SHIFT));
	ext_key.logical_addr = htole64(0);

	j_phys_ext_val_t ext_val;
	ext_val.len_and_flags = htole64(amp->am_block_size & EXTENT_LEN_MASK);
	ext_val.phys_addr = htole64((uint64_t)target_paddr);

	error = apfs_btree_insert_record(&tx, omap_oid, &root_tree_oid,
	    &ext_key, sizeof(ext_key), &ext_val, sizeof(ext_val));
	if (error != 0) {
		apfs_tx_abort(&tx);
		return error;
	}

	/* 4. Directory Entry Record */
	size_t drec_key_size = sizeof(j_drec_key_t) + name_len + 1;
	j_drec_key_t *drec_key = kmem_zalloc(drec_key_size, KM_SLEEP);
	drec_key->obj_id_and_type = htole64((parent_oid & OBJ_ID_MASK) |
	    ((uint64_t)APFS_TYPE_DIR_REC << OBJ_TYPE_SHIFT));
	drec_key->name_len_and_hash = htole32((name_hash << DREC_HASH_SHIFT) |
	    (name_len & DREC_NLEN_MASK));
	memcpy(drec_key->name, name, name_len);
	drec_key->name[name_len] = '\0';

	j_drec_val_t drec_val;
	memset(&drec_val, 0, sizeof(drec_val));
	drec_val.file_id = htole64(new_ino_oid);
	drec_val.date_added = htole64(now_ns);
	drec_val.flags = htole16(DT_LNK);

	error = apfs_btree_insert_record(&tx, omap_oid, &root_tree_oid,
	    drec_key, drec_key_size, &drec_val, sizeof(drec_val));
	kmem_free(drec_key, drec_key_size);
	if (error != 0) {
		apfs_tx_abort(&tx);
		return error;
	}

	/* Update superblock */
	uint64_t num_files = le64toh(amp->am_sb.apfs_num_files);
	amp->am_sb.apfs_num_files = htole64(num_files + 1);
	amp->am_sb.apfs_root_tree_oid = htole64(root_tree_oid);

	error = apfs_tx_commit(&tx);
	if (error != 0)
		return error;

	if (new_oidp != NULL)
		*new_oidp = new_ino_oid;

	return 0;
}

int
apfs_rename_file(struct apfsmount *amp, oid_t from_parent_oid, const char *from_name,
    oid_t to_parent_oid, const char *to_name, struct apfsnode *fnode, struct apfsnode *tnode)
{
	apfs_tx_t tx;
	oid_t root_tree_oid, omap_oid;
	uint32_t from_len = strlen(from_name);
	uint32_t to_len = strlen(to_name);
	uint64_t incompat_features = le64toh(amp->am_sb.apfs_incompatible_features);
	bool ci = (incompat_features & APFS_INCOMPAT_CASE_INSENSITIVE) != 0;
	bool ni = (incompat_features & APFS_INCOMPAT_NORMALIZATION_INSENSITIVE) != 0;
	uint32_t from_hash = 0, to_hash = 0;
	struct timespec ts;
	uint64_t now_ns;
	int error;

	if (amp == NULL || fnode == NULL)
		return EINVAL;

	error = apfs_name_hash(from_name, from_len, ci, ni, &from_hash);
	if (error != 0) return error;
	error = apfs_name_hash(to_name, to_len, ci, ni, &to_hash);
	if (error != 0) return error;

	nanotime(&ts);
	now_ns = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;

	/* If destination exists, remove it first */
	if (tnode != NULL) {
		if (tnode->a_vnode && tnode->a_vnode->v_type == VDIR) {
			error = apfs_remove_dir(amp, to_parent_oid, to_name, tnode->a_oid);
		} else {
			error = apfs_remove_file(amp, to_parent_oid, to_name, tnode->a_oid);
		}
		if (error != 0) return error;
	}

	error = apfs_tx_begin(amp, &tx);
	if (error != 0) return error;

	root_tree_oid = le64toh(amp->am_sb.apfs_root_tree_oid);
	omap_oid = le64toh(amp->am_sb.apfs_omap_oid);

	/* 1. Remove source DREC */
	size_t from_drec_key_size = sizeof(j_drec_key_t) + from_len + 1;
	j_drec_key_t *from_drec_key = kmem_zalloc(from_drec_key_size, KM_SLEEP);
	from_drec_key->obj_id_and_type = htole64((from_parent_oid & OBJ_ID_MASK) |
	    ((uint64_t)APFS_TYPE_DIR_REC << OBJ_TYPE_SHIFT));
	from_drec_key->name_len_and_hash = htole32((from_hash << DREC_HASH_SHIFT) |
	    (from_len & DREC_NLEN_MASK));
	memcpy(from_drec_key->name, from_name, from_len);
	from_drec_key->name[from_len] = '\0';

	error = apfs_btree_remove_record(&tx, omap_oid, &root_tree_oid,
	    from_drec_key, from_drec_key_size);
	kmem_free(from_drec_key, from_drec_key_size);
	if (error != 0) {
		apfs_tx_abort(&tx);
		return error;
	}

	/* 2. Insert destination DREC */
	size_t to_drec_key_size = sizeof(j_drec_key_t) + to_len + 1;
	j_drec_key_t *to_drec_key = kmem_zalloc(to_drec_key_size, KM_SLEEP);
	to_drec_key->obj_id_and_type = htole64((to_parent_oid & OBJ_ID_MASK) |
	    ((uint64_t)APFS_TYPE_DIR_REC << OBJ_TYPE_SHIFT));
	to_drec_key->name_len_and_hash = htole32((to_hash << DREC_HASH_SHIFT) |
	    (to_len & DREC_NLEN_MASK));
	memcpy(to_drec_key->name, to_name, to_len);
	to_drec_key->name[to_len] = '\0';

	uint16_t drec_flags = (fnode->a_vnode && fnode->a_vnode->v_type == VDIR) ? DT_DIR :
	    ((fnode->a_vnode && fnode->a_vnode->v_type == VLNK) ? DT_LNK : DT_REG);
	j_drec_val_t to_drec_val;
	memset(&to_drec_val, 0, sizeof(to_drec_val));
	to_drec_val.file_id = htole64(fnode->a_oid);
	to_drec_val.date_added = htole64(now_ns);
	to_drec_val.flags = htole16(drec_flags);

	error = apfs_btree_insert_record(&tx, omap_oid, &root_tree_oid,
	    to_drec_key, to_drec_key_size, &to_drec_val, sizeof(to_drec_val));
	kmem_free(to_drec_key, to_drec_key_size);
	if (error != 0) {
		apfs_tx_abort(&tx);
		return error;
	}

	/* 3. If parent changed, update inode parent_id */
	if (from_parent_oid != to_parent_oid) {
		fnode->a_ino.parent_id = to_parent_oid;
		fnode->a_ino.change_time = now_ns;
		error = apfs_update_inode(&tx, fnode);
		if (error != 0) {
			apfs_tx_abort(&tx);
			return error;
		}
	}

	amp->am_sb.apfs_root_tree_oid = htole64(root_tree_oid);
	return apfs_tx_commit(&tx);
}

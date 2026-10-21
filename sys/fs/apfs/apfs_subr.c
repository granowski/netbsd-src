/*	$NetBSD$	*/
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/endian.h>
#include <sys/buf.h>
#include <sys/kmem.h>
#include <sys/sha2.h>
#include <fs/apfs/apfs.h>

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

/* OMap resolution: virtual OID -> physical block address */
int
apfs_omap_lookup(struct apfsmount *amp, oid_t omap_oid, oid_t oid, xid_t xid, apfs_paddr_t *paddrp)
{
    struct buf *bp;
    omap_phys_t *omap;
    omap_key_t key;
    omap_key_t found_key;
    omap_val_t val;
    uint64_t calculated_cksum, stored_cksum;
    uint64_t block_count;
    uint32_t tree_type;
    int error;

    if (omap_oid == 0) {
        printf("apfs_omap_lookup: omap_oid is 0\n");
        return EINVAL;
    }

    error = apfs_bread(amp, (apfs_paddr_t)omap_oid, &bp);
    if (error != 0)
        return error;

    omap = (omap_phys_t *)bp->b_data;
    calculated_cksum = apfs_fletcher64(bp->b_data, amp->am_block_size);
    memcpy(&stored_cksum, omap->omap_o.o_cksum, sizeof(stored_cksum));
    stored_cksum = le64toh(stored_cksum);
    if (calculated_cksum != stored_cksum) {
        printf("apfs_omap_lookup: OMap checksum mismatch at APFS block "
            "%llu: calculated 0x%016llx, disk 0x%016llx\n",
            (unsigned long long)omap_oid,
            (unsigned long long)calculated_cksum,
            (unsigned long long)stored_cksum);
        brelse(bp, 0);
        return EINVAL;
    }
    if (le64toh(omap->omap_o.o_oid) != omap_oid ||
        (le32toh(omap->omap_o.o_type) & OBJECT_TYPE_MASK) != OBJ_OMAP) {
        printf("apfs_omap_lookup: invalid OMap object at APFS block %llu "
            "(oid 0x%llx type 0x%x)\n",
            (unsigned long long)omap_oid,
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
    uint32_t tree_flags, oid_t child_oid, apfs_paddr_t *paddrp)
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
	return apfs_omap_lookup(amp, omap_oid, child_oid,
	    amp->am_checkpoint_xid, paddrp);
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
        if ((tree_subtype & OBJECT_TYPE_MASK) == OBJ_FSTREE) {
            printf("apfs_btree_search: filesystem tree 0x%llx node "
                "block %lld oid 0x%llx type 0x%x subtype 0x%x "
                "flags 0x%x level %u keys %u tree flags 0x%x "
                "table off %u len %u free off %u len %u "
                "info key size %u val size %u node size %u "
                "node count %llu\n",
                (unsigned long long)tree_oid, (long long)paddr,
                (unsigned long long)le64toh(node->btn_o.o_oid),
                node_type, le32toh(node->btn_o.o_subtype), node_flags,
                le16toh(node->btn_level), nkeys, tree_flags,
                le16toh(node->btn_table_space_off),
                le16toh(node->btn_table_space_len),
                le16toh(node->btn_free_space_off),
                le16toh(node->btn_free_space_len),
                le32toh(info.bt_key_size), le32toh(info.bt_val_size),
                le32toh(info.bt_node_size),
                (unsigned long long)le64toh(info.bt_node_count));
            if ((node_flags & BTNODE_ROOT) != 0) {
                uint64_t key0 = 0, key1 = 0;

                memcpy(&key0, key, MIN(key_len, sizeof(key0)));
                if (key_len > sizeof(key0))
                    memcpy(&key1, (const uint8_t *)key + sizeof(key0),
                        MIN(key_len - sizeof(key0), sizeof(key1)));
                printf("apfs_btree_search: filesystem tree 0x%llx "
                    "request key len %zu words 0x%llx/0x%llx "
                    "oid 0x%llx type 0x%llx value size %zu\n",
                    (unsigned long long)tree_oid, key_len,
                    (unsigned long long)le64toh(key0),
                    (unsigned long long)le64toh(key1),
                    (unsigned long long)(le64toh(key0) & OBJ_ID_MASK),
                    (unsigned long long)((le64toh(key0) & OBJ_TYPE_MASK) >>
                    OBJ_TYPE_SHIFT), val_size);
            }
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
            if ((tree_subtype & OBJECT_TYPE_MASK) == OBJ_FSTREE) {
                uint64_t entry_key0 = 0;

                if (k_len >= sizeof(entry_key0))
                    memcpy(&entry_key0, k_ptr, sizeof(entry_key0));
                printf("apfs_btree_search: filesystem tree 0x%llx "
                    "block %lld %s probe %d key len %zu word 0x%llx "
                    "oid 0x%llx type 0x%llx value len %zu cmp %d "
                    "range %d..%d\n",
                    (unsigned long long)tree_oid, (long long)paddr,
                    (node_flags & BTNODE_LEAF) != 0 ? "leaf" : "node",
                    mid, k_len, (unsigned long long)le64toh(entry_key0),
                    (unsigned long long)(le64toh(entry_key0) &
                    OBJ_ID_MASK),
                    (unsigned long long)((le64toh(entry_key0) &
                    OBJ_TYPE_MASK) >> OBJ_TYPE_SHIFT),
                    v_len, cmp, low, high);
                if (((le64toh(entry_key0) & OBJ_TYPE_MASK) >>
                    OBJ_TYPE_SHIFT) == APFS_TYPE_DIR_REC &&
                    k_len >= sizeof(j_drec_key_t) &&
                    key_len >= sizeof(j_drec_key_t)) {
                    const j_drec_key_t *entry_drec = k_ptr;
                    const j_drec_key_t *request_drec = key;
                    uint32_t entry_name_len = le32toh(
                        entry_drec->name_len_and_hash) & DREC_NLEN_MASK;
                    uint32_t request_name_len = le32toh(
                        request_drec->name_len_and_hash) & DREC_NLEN_MASK;
                    uint32_t entry_name_available =
                        k_len - sizeof(*entry_drec);
                    uint32_t request_name_available =
                        key_len - sizeof(*request_drec);

                    entry_name_len = MIN(entry_name_len,
                        entry_name_available);
                    request_name_len = MIN(request_name_len,
                        request_name_available);
                    printf("apfs_btree_search: DREC probe entry hash "
                        "0x%x name '%.*s' request hash 0x%x name "
                        "'%.*s'\n",
                        (le32toh(entry_drec->name_len_and_hash) &
                        DREC_HASH_MASK) >> DREC_HASH_SHIFT,
                        (int)entry_name_len, entry_drec->name,
                        (le32toh(request_drec->name_len_and_hash) &
                        DREC_HASH_MASK) >> DREC_HASH_SHIFT,
                        (int)request_name_len, request_drec->name);
                }
            }

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
            if ((tree_subtype & OBJECT_TYPE_MASK) == OBJ_FSTREE &&
                key_len >= sizeof(uint64_t)) {
                uint64_t requested_key = 0;

                memcpy(&requested_key, key, sizeof(requested_key));
                if (((le64toh(requested_key) & OBJ_TYPE_MASK) >>
                    OBJ_TYPE_SHIFT) ==
                    APFS_TYPE_INODE) {
                    printf("apfs_btree_search: dumping %u leaf entries "
                        "for inode key 0x%llx in block %lld\n",
                        nkeys, (unsigned long long)le64toh(requested_key),
                        (long long)paddr);
                    for (uint32_t i = 0; i < nkeys; i++) {
                        const void *dump_key, *dump_val;
                        size_t dump_key_len, dump_val_len;
                        uint64_t key0 = 0, key1 = 0, val0 = 0, val1 = 0;
                        int dump_error;

                        dump_error = apfs_btree_entry(amp, node, &info, i,
                            &dump_key, &dump_key_len, &dump_val,
                            &dump_val_len);
                        if (dump_error != 0) {
                            printf("apfs_btree_search: leaf entry %u "
                                "decode error %d\n", i, dump_error);
                            continue;
                        }
                        if (dump_key_len >= sizeof(key0))
                            memcpy(&key0, dump_key, sizeof(key0));
                        if (dump_key_len > sizeof(key0))
                            memcpy(&key1, (const uint8_t *)dump_key +
                                sizeof(key0), MIN(dump_key_len -
                                sizeof(key0), sizeof(key1)));
                        if (dump_val_len >= sizeof(val0))
                            memcpy(&val0, dump_val, sizeof(val0));
                        if (dump_val_len > sizeof(val0))
                            memcpy(&val1, (const uint8_t *)dump_val +
                                sizeof(val0), MIN(dump_val_len -
                                sizeof(val0), sizeof(val1)));
                        printf("apfs_btree_search: leaf entry %u key "
                            "len %zu words 0x%llx/0x%llx value len %zu "
                            "words 0x%llx/0x%llx cmp %d\n", i,
                            dump_key_len,
                            (unsigned long long)le64toh(key0),
                            (unsigned long long)le64toh(key1),
                            dump_val_len,
                            (unsigned long long)le64toh(val0),
                            (unsigned long long)le64toh(val1),
                            apfs_key_compare(tree_subtype, key, key_len,
                            dump_key, dump_key_len));
                    }
                }
            }
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
            if ((tree_subtype & OBJECT_TYPE_MASK) == OBJ_OMAP &&
                k_len >= sizeof(omap_key_t) && v_len >= sizeof(omap_val_t)) {
                const omap_key_t *omap_key = k_ptr;
                const omap_val_t *omap_val = v_ptr;

                printf("apfs_btree_search: OMap leaf block %lld oid "
                    "0x%llx level %u selected key (0x%llx,0x%llx) "
                    "value flags 0x%x size %u paddr %llu\n",
                    (long long)paddr,
                    (unsigned long long)le64toh(node->btn_o.o_oid),
                    le16toh(node->btn_level),
                    (unsigned long long)le64toh(omap_key->ok_oid),
                    (unsigned long long)le64toh(omap_key->ok_xid),
                    le32toh(omap_val->ov_flags),
                    le32toh(omap_val->ov_size),
                    (unsigned long long)le64toh(
                    (uint64_t)omap_val->ov_paddr));
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
                if ((tree_subtype & OBJECT_TYPE_MASK) == OBJ_FSTREE &&
                    key_len >= sizeof(uint64_t) &&
                    k_len >= sizeof(uint64_t)) {
                    printf("apfs_btree_search: filesystem tree 0x%llx "
                        "key miss in block %lld (requested 0x%llx, "
                        "selected 0x%llx)\n",
                        (unsigned long long)tree_oid, (long long)paddr,
                        (unsigned long long)le64toh(
                        *(const uint64_t *)key),
                        (unsigned long long)le64toh(
                        *(const uint64_t *)k_ptr));
                }
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
            if ((tree_subtype & OBJECT_TYPE_MASK) == OBJ_FSTREE) {
                uint64_t entry_key0 = 0, requested_key = 0;

                if (k_len >= sizeof(entry_key0))
                    memcpy(&entry_key0, k_ptr, sizeof(entry_key0));
                if (key_len >= sizeof(requested_key))
                    memcpy(&requested_key, key, sizeof(requested_key));
                printf("apfs_btree_search: filesystem tree 0x%llx "
                    "block %lld chose separator %d key len %zu "
                    "word 0x%llx child 0x%llx request 0x%llx "
                    "cmp %d search range %d..%d\n",
                    (unsigned long long)tree_oid, (long long)paddr, mid,
                    k_len, (unsigned long long)le64toh(entry_key0),
                    (unsigned long long)child_oid,
                    (unsigned long long)le64toh(requested_key),
                    apfs_key_compare(tree_subtype, key, key_len,
                    k_ptr, k_len), low, high);
            }
            if ((tree_subtype & OBJECT_TYPE_MASK) == OBJ_OMAP &&
                k_len >= sizeof(omap_key_t)) {
                const omap_key_t *omap_key = k_ptr;

                printf("apfs_btree_search: OMap internal block %lld oid "
                    "0x%llx level %u chose entry %d key (0x%llx,0x%llx) "
                    "child 0x%llx\n",
                    (long long)paddr,
                    (unsigned long long)le64toh(node->btn_o.o_oid),
                    le16toh(node->btn_level), mid,
                    (unsigned long long)le64toh(omap_key->ok_oid),
                    (unsigned long long)le64toh(omap_key->ok_xid),
                    (unsigned long long)child_oid);
            }
            if ((tree_flags & BTREE_HASHED) != 0) {
                const btree_index_node_val_t *index_val = v_ptr;
                memcpy(expected_hash, index_val->child_hash,
                    sizeof(expected_hash));
                have_expected_hash = true;
            }
            brelse(bp, 0);
            error = apfs_btree_resolve_child(amp, omap_oid, tree_flags,
                child_oid, &paddr);
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
	enum { APFS_BTREE_MAX_DEPTH = 64 };
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
		error = apfs_btree_resolve_child(amp, omap_oid, tree_flags,
		    child_oid, &stack[depth].paddr);
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

/* B-Tree Insertion with COW Cascade */
int
apfs_btree_insert(struct apfsmount *amp, oid_t *tree_oid, void *key, void *val)
{
    /* 
     * 1. Traverse down to leaf, keeping path in memory.
     * 2. Check if leaf has space.
     * 3. If no space, split leaf and propagate split up (COW).
     * 4. Write new nodes to new blocks (apfs_alloc_block).
     * 5. Update parent pointers to new block addresses.
     * 6. Update OMap for the new nodes.
     * 7. Finally update the tree root OID if it changed.
     */
    return EOPNOTSUPP; /* Huge implementation task */
}

/* Space Manager: Allocate a new block */
int
apfs_alloc_block(struct apfsmount *amp, apfs_paddr_t *paddrp)
{
    mutex_enter(&amp->am_lock);
    /* 
     * 1. Read Space Manager (spaceman) object.
     * 2. Search free-queue or bitmap for a free block.
     * 3. Mark block as used.
     * 4. Update spaceman counters.
     * 5. COW the spaceman object and its B-trees.
     */
    *paddrp = amp->am_nx.nx_xp_data_base + (amp->am_sb.apfs_fs_alloc_count++);
    mutex_exit(&amp->am_lock);
    return 0;
}

int
apfs_free_block(struct apfsmount *amp, apfs_paddr_t paddr)
{
    return 0;
}

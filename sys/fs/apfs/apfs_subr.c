/*	$NetBSD$	*/
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/endian.h>
#include <sys/buf.h>
#include <sys/kmem.h>
#include <fs/apfs/apfs.h>

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
	    desc_blocks > block_count - desc_base)
		return false;
	if (((uint64_t)desc_index + desc_len - 1) % desc_blocks !=
	    desc_slot)
		return false;

	capacity = (amp->am_block_size - sizeof(*map)) /
	    sizeof(checkpoint_mapping_t);
	for (i = 0; i < desc_len; i++) {
		uint32_t index = ((uint64_t)desc_index + i) % desc_blocks;
		apfs_paddr_t paddr = (apfs_paddr_t)(desc_base + index);
		uint32_t flags;
		int error = apfs_bread(amp, paddr, &bp);

		if (error != 0)
			return false;
		map = (checkpoint_map_phys_t *)bp->b_data;
		if ((le32toh(map->cpm_o.o_type) & OBJECT_TYPE_MASK) !=
		    OBJ_CHECKPOINT_MAP ||
		    le64toh(map->cpm_o.o_xid) != xid) {
			brelse(bp, 0);
			continue;
		}
		if (le64toh(map->cpm_o.o_oid) != (uint64_t)paddr ||
		    !apfs_checksum_valid(amp, map)) {
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
			uint64_t paddr = le64toh((uint64_t)entry->cpm_paddr);
			uint32_t storage = le32toh(entry->cpm_type) &
			    OBJ_STORAGE_MASK;
			uint64_t blocks;

			if (oid == 0 || size == 0 || storage != OBJ_EPHEMERAL ||
			    paddr >= block_count) {
				brelse(bp, 0);
				return false;
			}
			blocks = howmany(size, amp->am_block_size);
			if (blocks > block_count - paddr) {
				brelse(bp, 0);
				return false;
			}
		}
		found_map = true;
		found_last |= (flags & CHECKPOINT_MAP_LAST) != 0;
		brelse(bp, 0);
	}

	return found_map && found_last;
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

		error = apfs_bread(amp, (apfs_paddr_t)(desc_base + i), &bp);
		if (error != 0)
			continue;
		memcpy(&candidate, bp->b_data, sizeof(candidate));
		type = le32toh(candidate.nx_o.o_type) & OBJECT_TYPE_MASK;
		xid = le64toh(candidate.nx_o.o_xid);
		if (type != OBJ_CONTAINER_SUPERBLOCK || xid <= selected_xid ||
		    le32toh(candidate.nx_magic) != NX_MAGIC ||
		    le32toh(candidate.nx_block_size) != amp->am_block_size ||
		    !apfs_checksum_valid(amp, bp->b_data)) {
			brelse(bp, 0);
			continue;
		}
		brelse(bp, 0);

		if (le32toh(candidate.nx_max_file_systems) >
		    NX_MAX_FILE_SYSTEMS ||
		    le64toh(candidate.nx_block_count) != block_count ||
		    le64toh(candidate.nx_xp_desc_base) != desc_base ||
		    le32toh(candidate.nx_xp_desc_blocks) != desc_blocks ||
		    !apfs_checkpoint_maps_valid(amp, &candidate, desc_blocks, i,
		    xid))
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
    omap_val_t val;
    uint64_t calculated_cksum, stored_cksum;
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
    brelse(bp, 0);
    if (tree_oid == 0) {
        printf("apfs_omap_lookup: OMap object at APFS block %llu has no "
            "tree root\n", (unsigned long long)omap_oid);
        return EINVAL;
    }

    key.ok_oid = htole64(oid);
    key.ok_xid = htole64(xid);
    error = apfs_btree_search(amp, 0, tree_oid, &key, sizeof(key), &val,
        sizeof(val), NULL, 0);
    if (error == 0) {
        *paddrp = (apfs_paddr_t)le64toh((uint64_t)val.ov_paddr);
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

    if (kt1 < kt2) return -1;
    if (kt1 > kt2) return 1;

    /* Type and OID match, check subtypes */
    uint32_t subtype = kt1 & OBJ_TYPE_MASK;

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
	uint32_t key_area;

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
	    val_off > data_end || val_len > data_end - val_off ||
	    data_end - val_off - val_len < key_area)
		return EINVAL;

	*keyp = (uint8_t *)node + key_area + key_off;
	*key_lenp = key_len;
	*valp = (uint8_t *)node + data_end - val_off - val_len;
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
    size_t found_key_size)
{
    struct buf *bp;
    btree_node_phys_t *node;
    apfs_paddr_t paddr;
    btree_info_t info;
    uint32_t tree_flags = 0;
    bool have_info = false;
    uint64_t node_limit = 0;
    uint64_t steps = 0;
    int error;

    if (key_len == 0 || key_len > amp->am_block_size || val == NULL ||
        val_size == 0 || val_size > amp->am_block_size ||
        (found_key != NULL && found_key_size == 0))
        return EINVAL;

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
        if (!apfs_checksum_valid(amp, node)) {
            uint64_t stored_cksum;
            memcpy(&stored_cksum, node->btn_o.o_cksum,
                sizeof(stored_cksum));
            printf("apfs_btree_search: checksum mismatch at APFS block %lld "
                "(block size %u): calculated 0x%016llx, disk 0x%016llx; "
                "object oid 0x%llx xid 0x%llx type 0x%08x\n",
                (long long)paddr, amp->am_block_size,
                (unsigned long long)apfs_fletcher64(node,
                amp->am_block_size),
                (unsigned long long)stored_cksum,
                (unsigned long long)le64toh(node->btn_o.o_oid),
                (unsigned long long)le64toh(node->btn_o.o_xid),
                le32toh(node->btn_o.o_type));
            brelse(bp, 0);
            return EINVAL;
        }

        uint16_t node_flags = le16toh(node->btn_flags);
        uint32_t node_type = le32toh(node->btn_o.o_type) &
            OBJECT_TYPE_MASK;
        uint32_t nkeys = le32toh(node->btn_nkeys);
        if ((node_flags & BTNODE_ROOT) != 0) {
            if (node_type != OBJ_BTREE) {
                brelse(bp, 0);
                return EINVAL;
            }
            memcpy(&info, (uint8_t *)node + amp->am_block_size -
                sizeof(info), sizeof(info));
            tree_flags = le32toh(info.bt_flags);
            node_limit = le64toh(info.bt_node_count);
            have_info = true;
            if ((tree_flags & (BTREE_PHYSICAL | BTREE_EPHEMERAL)) ==
                (BTREE_PHYSICAL | BTREE_EPHEMERAL) ||
                (tree_flags & (BTREE_HASHED | BTREE_NOHEADER)) != 0 ||
                le32toh(info.bt_node_size) != amp->am_block_size ||
                node_limit == 0) {
                brelse(bp, 0);
                return EOPNOTSUPP;
            }
        } else if (node_type != OBJ_BTREE_NODE || !have_info) {
            brelse(bp, 0);
            return EINVAL;
        }
        if (++steps > node_limit + 1 || nkeys == 0) {
            brelse(bp, 0);
            return EINVAL;
        }

        int low = 0, high = (int)nkeys - 1;
        int mid, last_match = -1, cmp;
        const void *k_ptr, *v_ptr;
        size_t k_len, v_len;

        while (low <= high) {
            mid = (low + high) / 2;
            error = apfs_btree_entry(amp, node, &info, mid, &k_ptr,
                &k_len, &v_ptr, &v_len);
            if (error != 0) {
                brelse(bp, 0);
                return error;
            }
            cmp = apfs_key_compare(le32toh(node->btn_o.o_subtype),
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
                brelse(bp, 0);
                return error;
            }
            if (v_len < val_size) {
                brelse(bp, 0);
                return EINVAL;
            }
            memset(val, 0, val_size);
            memcpy(val, v_ptr, MIN(v_len, val_size));
            if (found_key != NULL) {
                if (k_len > found_key_size) {
                    brelse(bp, 0);
                    return EOVERFLOW;
                }
                memcpy(found_key, k_ptr, k_len);
            }
            int match_error = 0;
            if ((le32toh(node->btn_o.o_subtype) & OBJECT_TYPE_MASK) ==
                OBJ_OMAP) {
                const omap_key_t *requested = key;
                const omap_key_t *found = k_ptr;

                if (le64toh(requested->ok_oid) != le64toh(found->ok_oid) ||
                    le64toh(found->ok_xid) > le64toh(requested->ok_xid))
                    match_error = ENOENT;
            } else if ((le64toh(*(uint64_t *)key) & OBJ_TYPE_MASK) ==
                APFS_TYPE_EXTENT) {
                if (apfs_key_compare(
                    le32toh(node->btn_o.o_subtype), key, key_len, k_ptr,
                    k_len) < 0)
                    match_error = ENOENT;
            } else {
                if (apfs_key_compare(
                    le32toh(node->btn_o.o_subtype), key, key_len, k_ptr,
                    k_len) != 0)
                    match_error = ENOENT;
            }
            brelse(bp, 0);
            return match_error;
        } else {
            mid = (low > 0) ? low - 1 : 0;
            error = apfs_btree_entry(amp, node, &info, mid, &k_ptr,
                &k_len, &v_ptr, &v_len);
            if (error != 0 || v_len < sizeof(oid_t)) {
                brelse(bp, 0);
                return error != 0 ? error : EINVAL;
            }
            oid_t child_oid = le64toh(*(const oid_t *)v_ptr);
            brelse(bp, 0);
            error = apfs_btree_resolve_child(amp, omap_oid, tree_flags,
                child_oid, &paddr);
            if (error != 0)
                return error;
        }
    }
}

int
apfs_btree_iterate(struct apfsmount *amp, oid_t omap_oid, oid_t tree_oid, void *start_key, size_t key_len, apfs_btree_iter_cb cb, void *arg)
{
    struct buf *bp;
    btree_node_phys_t *node;
    apfs_paddr_t paddr;
    btree_info_t info;
    uint32_t tree_flags = 0;
    bool have_info = false;
    int error, i;
    size_t current_k_len = key_len;
    void *found_k = kmem_alloc(amp->am_block_size, KM_SLEEP);
    void *current_k = kmem_alloc(amp->am_block_size, KM_SLEEP);
    void *current_v = kmem_alloc(amp->am_block_size, KM_SLEEP);
    
    if (key_len > amp->am_block_size) {
        error = EINVAL;
        goto out_noalloc;
    }
    memcpy(current_k, start_key, key_len);

    while (1) {
        /* 1. Find the leaf node containing current_k */
        /* This is a bit inefficient but safe: we re-traverse for each leaf */
        error = apfs_btree_search(amp, omap_oid, tree_oid, current_k,
            current_k_len, current_v, amp->am_block_size, found_k,
            amp->am_block_size);
        if (error && error != ENOENT) goto out;

        /* Resolve paddr of the leaf again (btree_search doesn't return it) */
        /* We'll duplicate the search logic here to keep the buf */
        paddr = tree_oid;
        if (tree_oid != omap_oid && omap_oid != 0) {
            error = apfs_omap_lookup(amp, omap_oid, tree_oid,
                amp->am_checkpoint_xid, &paddr);
            if (error)
                goto out;
        }

        while (1) {
            error = apfs_bread(amp, paddr, &bp);
            if (error) goto out;
            node = (btree_node_phys_t *)bp->b_data;
            if (!apfs_checksum_valid(amp, node)) {
                brelse(bp, 0);
                error = EINVAL;
                goto out;
            }
            uint16_t node_flags = le16toh(node->btn_flags);
            if (node_flags & BTNODE_ROOT) {
                if ((le32toh(node->btn_o.o_type) & OBJECT_TYPE_MASK) !=
                    OBJ_BTREE) {
                    brelse(bp, 0);
                    error = EINVAL;
                    goto out;
                }
                memcpy(&info, (uint8_t *)node + amp->am_block_size -
                    sizeof(info), sizeof(info));
                tree_flags = le32toh(info.bt_flags);
                have_info = true;
                if ((tree_flags & (BTREE_PHYSICAL | BTREE_EPHEMERAL)) ==
                    (BTREE_PHYSICAL | BTREE_EPHEMERAL) ||
                    (tree_flags & (BTREE_HASHED | BTREE_NOHEADER)) != 0 ||
                    le32toh(info.bt_node_size) != amp->am_block_size ||
                    le64toh(info.bt_node_count) == 0) {
                    brelse(bp, 0);
                    error = EOPNOTSUPP;
                    goto out;
                }
            } else if (!have_info ||
                (le32toh(node->btn_o.o_type) & OBJECT_TYPE_MASK) !=
                OBJ_BTREE_NODE) {
                brelse(bp, 0);
                error = EINVAL;
                goto out;
            }
            if (node_flags & BTNODE_LEAF)
                break;

            uint32_t nkeys = le32toh(node->btn_nkeys);
            int low = 0, high = (int)nkeys - 1, mid;
            while (low <= high) {
                mid = (low + high) / 2;
                const void *k_ptr, *v_ptr;
                size_t k_len, v_len;
                error = apfs_btree_entry(amp, node, &info, mid, &k_ptr,
                    &k_len, &v_ptr, &v_len);
                if (error) {
                    brelse(bp, 0);
                    goto out;
                }
                if (apfs_key_compare(le32toh(node->btn_o.o_subtype),
                    current_k, current_k_len, k_ptr, k_len) < 0)
                    high = mid - 1;
                else
                    low = mid + 1;
            }
            i = (low > 0) ? low - 1 : 0;
            const void *k_ptr, *v_ptr;
            size_t k_len, v_len;
            error = apfs_btree_entry(amp, node, &info, i, &k_ptr,
                &k_len, &v_ptr, &v_len);
            if (error || v_len < sizeof(oid_t)) {
                brelse(bp, 0);
                if (error == 0)
                    error = EINVAL;
                goto out;
            }
            oid_t child_oid = le64toh(*(const oid_t *)v_ptr);
            brelse(bp, 0);
            error = apfs_btree_resolve_child(amp, omap_oid, tree_flags,
                child_oid, &paddr);
            if (error)
                goto out;
        }

        /* 2. Iterate all keys in this leaf >= current_k */
        uint32_t nkeys = le32toh(node->btn_nkeys);
        for (i = 0; i < nkeys; i++) {
            const void *k_ptr, *v_ptr;
            size_t k_len, v_len;
            error = apfs_btree_entry(amp, node, &info, i, &k_ptr,
                &k_len, &v_ptr, &v_len);
            if (error) {
                brelse(bp, 0);
                goto out;
            }
            
            if (apfs_key_compare(le32toh(node->btn_o.o_subtype),
                k_ptr, k_len, current_k, current_k_len) < 0)
                continue;

            error = cb(arg, k_ptr, k_len, v_ptr, v_len);
            if (error) {
                brelse(bp, 0);
                goto out;
            }
            
            /* Keep track of last key found to advance */
            memcpy(current_k, k_ptr, k_len);
            current_k_len = k_len;
        }

        /* 3. Advance to next leaf */
        brelse(bp, 0);
        break; /* Simplified */
    }
    error = 0;

out:
    kmem_free(found_k, amp->am_block_size);
    kmem_free(current_k, amp->am_block_size);
    kmem_free(current_v, amp->am_block_size);
out_noalloc:
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

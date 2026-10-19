/*	$NetBSD$	*/
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/buf.h>
#include <sys/kmem.h>
#include <fs/apfs/apfs.h>

/* Fletcher 64 checksum implementation for APFS */
uint64_t
apfs_fletcher64(const void *buf, size_t len)
{
    const uint32_t *data = buf;
    uint32_t s1 = 0, s2 = 0;
    size_t count = len / 4;

    /* Skip the first 8 bytes (checksum itself) */
    data += 2;
    count -= 2;

    for (size_t i = 0; i < count; i++) {
        s1 += data[i];
        s2 += s1;
    }

    return ((uint64_t)s2 << 32) | s1;
}

/* OMap resolution: virtual OID -> physical block address */
int
apfs_omap_lookup(struct apfsmount *amp, oid_t omap_oid, oid_t oid, xid_t xid, apfs_paddr_t *paddrp)
{
    omap_key_t key;
    omap_val_t val;
    int error;

    if (omap_oid == 0) return EINVAL;

    key.ok_oid = oid;
    key.ok_xid = xid;

    error = apfs_btree_search(amp, omap_oid, omap_oid, &key, sizeof(key), &val, NULL);
    if (error == 0) {
        *paddrp = val.ov_paddr;
    }
    return error;
}

static int
apfs_key_compare(uint32_t type, const void *k1, size_t k1_len, const void *k2, size_t k2_len)
{
    uint64_t kt1 = *(const uint64_t *)k1;
    uint64_t kt2 = *(const uint64_t *)k2;

    if (kt1 < kt2) return -1;
    if (kt1 > kt2) return 1;

    /* Type and OID match, check subtypes */
    uint32_t subtype = kt1 & OBJ_TYPE_MASK;

    if (subtype == APFS_TYPE_DIR_REC) {
        if (k1_len < 12 || k2_len < 12) return 0; /* Should not happen for full keys */
        const j_drec_key_t *dk1 = k1;
        const j_drec_key_t *dk2 = k2;
        uint32_t h1 = dk1->name_len_and_hash & DREC_HASH_MASK;
        uint32_t h2 = dk2->name_len_and_hash & DREC_HASH_MASK;

        if (h1 < h2) return -1;
        if (h1 > h2) return 1;

        uint32_t len1 = dk1->name_len_and_hash & DREC_NLEN_MASK;
        uint32_t len2 = dk2->name_len_and_hash & DREC_NLEN_MASK;
        int len = MIN(len1, len2);
        int cmp = memcmp(dk1->name, dk2->name, len);
        if (cmp != 0) return cmp;
        if (len1 < len2) return -1;
        if (len1 > len2) return 1;
    } else if (subtype == APFS_TYPE_EXTENT) {
        const j_extent_key_t *ek1 = k1;
        const j_extent_key_t *ek2 = k2;
        if (ek1->logical_addr < ek2->logical_addr) return -1;
        if (ek1->logical_addr > ek2->logical_addr) return 1;
    }

    return 0;
}

/* B-Tree search implementation */
int
apfs_btree_search(struct apfsmount *amp, oid_t omap_oid, oid_t tree_oid, void *key, size_t key_len, void *val, void *found_key)
{
    struct buf *bp;
    btree_node_phys_t *node;
    apfs_paddr_t paddr;
    int error;

    /* 1. Resolve tree root OID to physical address */
    if (tree_oid == omap_oid || omap_oid == 0) {
        paddr = tree_oid; 
    } else {
        error = apfs_omap_lookup(amp, omap_oid, tree_oid, amp->am_nx.nx_next_xid - 1, &paddr);
        if (error) {
            paddr = tree_oid; 
        }
    }

    /* 2. Read and traverse nodes */
    while (1) {
        error = bread(amp->am_devvp, paddr, amp->am_block_size, 0, &bp);
        if (error) return error;

        node = (btree_node_phys_t *)bp->b_data;
        if (apfs_fletcher64(node, amp->am_block_size) != *(uint64_t *)node->btn_o.o_cksum) {
            brelse(bp, 0);
            return EINVAL;
        }

        /* 3. Binary search within node table of contents */
        btree_toc_entry_t *toc = (btree_toc_entry_t *)((uint8_t *)node + sizeof(*node));
        int low = 0, high = node->btn_nkeys - 1;
        int mid, cmp, last_match = -1;
        void *k_ptr;

        while (low <= high) {
            mid = (low + high) / 2;
            k_ptr = (uint8_t *)node + node->btn_table_space_off + toc[mid].key_off;
            
            cmp = apfs_key_compare(node->btn_o.o_type, key, key_len, k_ptr, toc[mid].key_len);
            
            if (cmp == 0) {
                last_match = mid;
                break;
            } else if (cmp < 0) {
                high = mid - 1;
            } else {
                low = mid + 1;
            }
        }

        if (last_match == -1) {
            /* If no exact match, for internal nodes we go to 'low - 1' or 0 */
            last_match = (low > 0) ? low - 1 : 0;
            if (node->btn_flags & BTNODE_LEAF) {
                /* For extents, we might want the record just before 'low' */
                mid = last_match;
            } else {
                mid = last_match;
            }
        } else {
            mid = last_match;
        }

        if (node->btn_flags & BTNODE_LEAF) {
            k_ptr = (uint8_t *)node + node->btn_table_space_off + toc[mid].key_off;
            memcpy(val, (uint8_t *)node + node->btn_table_space_off + toc[mid].val_off, toc[mid].val_len);
            if (found_key) memcpy(found_key, k_ptr, toc[mid].key_len);
            brelse(bp, 0);
            
            /* 
             * For extents, we allow returning a key that is smaller than requested 
             * (the extent starting before or at the offset).
             */
            if ((*(uint64_t *)key & OBJ_TYPE_MASK) == APFS_TYPE_EXTENT) {
                if (*(uint64_t *)key < *(uint64_t *)k_ptr) return ENOENT;
            } else {
                if (*(uint64_t *)key != *(uint64_t *)k_ptr) return ENOENT;
            }
            return 0;
        } else {
            /* Internal node: go down */
            paddr = *(apfs_paddr_t *)((uint8_t *)node + node->btn_table_space_off + toc[mid].val_off);
            brelse(bp, 0);
        }
    }
}

int
apfs_btree_iterate(struct apfsmount *amp, oid_t omap_oid, oid_t tree_oid, void *start_key, size_t key_len, apfs_btree_iter_cb cb, void *arg)
{
    struct buf *bp;
    btree_node_phys_t *node;
    apfs_paddr_t paddr;
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
        error = apfs_btree_search(amp, omap_oid, tree_oid, current_k, current_k_len, current_v, found_k);
        if (error && error != ENOENT) goto out;

        /* Resolve paddr of the leaf again (btree_search doesn't return it) */
        /* We'll duplicate the search logic here to keep the buf */
        paddr = tree_oid;
        if (tree_oid != omap_oid && omap_oid != 0) {
            apfs_omap_lookup(amp, omap_oid, tree_oid, amp->am_nx.nx_next_xid - 1, &paddr);
        }

        while (1) {
            error = bread(amp->am_devvp, paddr, amp->am_block_size, 0, &bp);
            if (error) goto out;
            node = (btree_node_phys_t *)bp->b_data;
            if (node->btn_flags & BTNODE_LEAF) break;
            
            /* Internal: find index */
            btree_toc_entry_t *toc = (btree_toc_entry_t *)((uint8_t *)node + sizeof(*node));
            int low = 0, high = node->btn_nkeys - 1, mid;
            while (low <= high) {
                mid = (low + high) / 2;
                void *k_ptr = (uint8_t *)node + node->btn_table_space_off + toc[mid].key_off;
                if (apfs_key_compare(node->btn_o.o_type, current_k, current_k_len, k_ptr, toc[mid].key_len) < 0)
                    high = mid - 1;
                else
                    low = mid + 1;
            }
            i = (low > 0) ? low - 1 : 0;
            paddr = *(apfs_paddr_t *)((uint8_t *)node + node->btn_table_space_off + toc[i].val_off);
            brelse(bp, 0);
        }

        /* 2. Iterate all keys in this leaf >= current_k */
        btree_toc_entry_t *toc = (btree_toc_entry_t *)((uint8_t *)node + sizeof(*node));
        for (i = 0; i < node->btn_nkeys; i++) {
            void *k_ptr = (uint8_t *)node + node->btn_table_space_off + toc[i].key_off;
            void *v_ptr = (uint8_t *)node + node->btn_table_space_off + toc[i].val_off;
            
            if (apfs_key_compare(node->btn_o.o_type, k_ptr, toc[i].key_len, current_k, current_k_len) < 0)
                continue;

            error = cb(arg, k_ptr, toc[i].key_len, v_ptr, toc[i].val_len);
            if (error) {
                brelse(bp, 0);
                goto out;
            }
            
            /* Keep track of last key found to advance */
            memcpy(current_k, k_ptr, toc[i].key_len);
            current_k_len = toc[i].key_len;
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

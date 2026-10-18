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
apfs_omap_lookup(struct apfsmount *amp, oid_t oid, xid_t xid, apfs_paddr_t *paddrp)
{
    omap_key_t key;
    omap_val_t val;
    int error;

    key.ok_oid = oid;
    key.ok_xid = xid;

    error = apfs_btree_search(amp, amp->am_sb.apfs_omap_oid, &key, &val, NULL);
    if (error == 0) {
        *paddrp = val.ov_paddr;
    }
    return error;
}

/* B-Tree search implementation */
int
apfs_btree_search(struct apfsmount *amp, oid_t tree_oid, void *key, void *val, void *found_key)
{
    struct buf *bp;
    btree_node_phys_t *node;
    apfs_paddr_t paddr;
    int error;

    /* 1. Resolve tree root OID to physical address */
    error = apfs_omap_lookup(amp, tree_oid, amp->am_nx.nx_next_xid - 1, &paddr);
    if (error) {
        /* Fallback for system objects not in OMap or during bootstrap */
        paddr = tree_oid; /* Simplified for now */
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
        int mid, cmp;
        void *k_ptr;

        while (low <= high) {
            mid = (low + high) / 2;
            k_ptr = (uint8_t *)node + node->btn_table_space_off + toc[mid].key_off;
            
            /* TODO: Implement generic key comparison based on tree type */
            cmp = memcmp(key, k_ptr, toc[mid].key_len);
            
            if (cmp == 0) {
                if (node->btn_flags & BTNODE_LEAF) {
                    memcpy(val, (uint8_t *)node + node->btn_table_space_off + toc[mid].val_off, toc[mid].val_len);
                    if (found_key) memcpy(found_key, k_ptr, toc[mid].key_len);
                    brelse(bp, 0);
                    return 0;
                } else {
                    /* Match in internal node, go down */
                    paddr = *(apfs_paddr_t *)((uint8_t *)node + node->btn_table_space_off + toc[mid].val_off);
                    brelse(bp, 0);
                    goto next_level;
                }
            } else if (cmp < 0) {
                high = mid - 1;
            } else {
                low = mid + 1;
            }
        }

        /* If not found and leaf, error */
        if (node->btn_flags & BTNODE_LEAF) {
            brelse(bp, 0);
            return ENOENT;
        }

        /* If not found and internal, follow the pointer to the left of 'low' */
        mid = (low > 0) ? low - 1 : 0;
        paddr = *(apfs_paddr_t *)((uint8_t *)node + node->btn_table_space_off + toc[mid].val_off);
        brelse(bp, 0);

next_level:
        continue;
    }
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

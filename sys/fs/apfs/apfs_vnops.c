/*	$NetBSD$	*/

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/buf.h>
#include <sys/dirent.h>
#include <sys/kmem.h>

#include <miscfs/genfs/genfs.h>

#include <fs/apfs/apfs.h>

/* Global vnode operation descriptors */
int (**apfs_vnodeop_p)(void *);
const struct vnodeopv_entry_desc apfs_vnodeop_entries[] = {
	{ &vop_default_desc, vn_default_error },
	{ &vop_parsepath_desc, genfs_parsepath },
	{ &vop_lookup_desc, apfs_vop_lookup },
	{ &vop_create_desc, apfs_vop_create },
	{ &vop_mknod_desc, apfs_vop_mknod },
	{ &vop_open_desc, apfs_vop_open },
	{ &vop_close_desc, apfs_vop_close },
	{ &vop_access_desc, apfs_vop_access },
	{ &vop_getattr_desc, apfs_vop_getattr },
	{ &vop_setattr_desc, apfs_vop_setattr },
	{ &vop_read_desc, apfs_vop_read },
	{ &vop_write_desc, apfs_vop_write },
	{ &vop_fsync_desc, apfs_vop_fsync },
	{ &vop_remove_desc, apfs_vop_remove },
	{ &vop_mkdir_desc, apfs_vop_mkdir },
	{ &vop_rmdir_desc, apfs_vop_rmdir },
	{ &vop_readdir_desc, apfs_vop_readdir },
	{ &vop_inactive_desc, apfs_vop_inactive },
	{ &vop_reclaim_desc, apfs_vop_reclaim },
	{ &vop_lock_desc, genfs_lock },
	{ &vop_unlock_desc, genfs_unlock },
	{ &vop_islocked_desc, genfs_islocked },
	{ &vop_strategy_desc, apfs_vop_strategy },
	{ &vop_bmap_desc, apfs_vop_bmap },
	{ NULL, NULL }
};
const struct vnodeopv_desc apfs_vnodeop_opv_desc =
	{ &apfs_vnodeop_p, apfs_vnodeop_entries };

const struct vnodeopv_desc * const apfs_vnodeopv_descs[] = {
	&apfs_vnodeop_opv_desc,
	NULL,
};

int
apfs_vop_lookup(void *v)
{
	struct vop_lookup_v2_args *ap = v;
	struct vnode *dvp = ap->a_dvp;
	struct componentname *cnp = ap->a_cnp;
	struct apfsnode *dnode = VTOA(dvp);
	j_drec_key_t *key;
	j_drec_val_t val;
	int error;

	if (cnp->cn_nameptr[0] == '.') {
		if (cnp->cn_namelen == 1) {
			*ap->a_vpp = dvp;
			vref(dvp);
			return 0;
		}
		if (cnp->cn_namelen == 2 && cnp->cn_nameptr[1] == '.') {
			return apfs_vget(dvp->v_mount, dnode->a_ino.parent_id, LK_EXCLUSIVE, ap->a_vpp);
		}
	}

	key = kmem_alloc(sizeof(*key) + cnp->cn_namelen, KM_SLEEP);
	key->parent_id = ((uint64_t)dnode->a_oid << 4) | APFS_TYPE_DIR_REC;
	key->name_len = cnp->cn_namelen;
	memcpy(key->name, cnp->cn_nameptr, cnp->cn_namelen);

	error = apfs_btree_search(dnode->a_amp, dnode->a_amp->am_sb.apfs_root_tree_oid, key, &val, NULL);
	kmem_free(key, sizeof(*key) + cnp->cn_namelen);

	if (error == 0) {
		return apfs_vget(dvp->v_mount, val.file_id, LK_EXCLUSIVE, ap->a_vpp);
	}

	return error;
}

int
apfs_vop_create(void *v)
{
	struct vop_create_v3_args *ap = v;
	struct vnode *dvp = ap->a_dvp;
	struct componentname *cnp = ap->a_cnp;
	struct vattr *vap = ap->a_vap;
	
	(void)dvp;
	(void)cnp;
	(void)vap;

	/* TODO: 
	 * 1. Allocate new OID.
	 * 2. Create inode record.
	 * 3. Insert into Root Tree (COW).
	 * 4. Add DREC to parent directory (COW).
	 * 5. Update parent directory mod time.
	 */
	
	return EOPNOTSUPP;
}

int
apfs_vop_mknod(void *v)
{
	return EOPNOTSUPP;
}

int
apfs_vop_open(void *v)
{
	return 0;
}

int
apfs_vop_close(void *v)
{
	return 0;
}

int
apfs_vop_access(void *v)
{
	struct vop_access_args *ap = v;
	struct vnode *vp = ap->a_vp;
	struct apfsnode *apnode = VTOA(vp);

	return genfs_can_access(vp, ap->a_cred, apnode->a_ino.owner,
	    apnode->a_ino.group, apnode->a_ino.mode, NULL, ap->a_accmode);
}

int
apfs_vop_getattr(void *v)
{
	struct vop_getattr_args *ap = v;
	struct vnode *vp = ap->a_vp;
	struct vattr *vap = ap->a_vap;
	struct apfsnode *apnode = VTOA(vp);

	vattr_null(vap);
	vap->va_type = vp->v_type;
	vap->va_mode = apnode->a_ino.mode;
	vap->va_nlink = apnode->a_ino.nlink;
	vap->va_uid = apnode->a_ino.owner;
	vap->va_gid = apnode->a_ino.group;
	vap->va_fsid = vp->v_mount->mnt_stat.f_fsidx.__fsid_val[0];
	vap->va_fileid = apnode->a_oid;
	vap->va_size = apnode->a_ino.uncompressed_size;
	vap->va_blocksize = apnode->a_amp->am_block_size;
	
	/* APFS timestamps are in nanoseconds since 1970-01-01 */
	vap->va_atime.tv_sec = apnode->a_ino.access_time / 1000000000;
	vap->va_atime.tv_nsec = apnode->a_ino.access_time % 1000000000;
	vap->va_mtime.tv_sec = apnode->a_ino.mod_time / 1000000000;
	vap->va_mtime.tv_nsec = apnode->a_ino.mod_time % 1000000000;
	vap->va_ctime.tv_sec = apnode->a_ino.change_time / 1000000000;
	vap->va_ctime.tv_nsec = apnode->a_ino.change_time % 1000000000;
	vap->va_birthtime.tv_sec = apnode->a_ino.create_time / 1000000000;
	vap->va_birthtime.tv_nsec = apnode->a_ino.create_time % 1000000000;

	return 0;
}

int
apfs_vop_setattr(void *v)
{
	struct vop_setattr_args *ap = v;
	struct vnode *vp = ap->a_vp;
	struct vattr *vap = ap->a_vap;
	struct apfsnode *apnode = VTOA(vp);
	
	(void)vap;
	(void)apnode;

	/* TODO: Update inode record and COW Root Tree */
	
	return EOPNOTSUPP;
}

int
apfs_vop_read(void *v)
{
	struct vop_read_args *ap = v;
	struct vnode *vp = ap->a_vp;
	struct uio *uio = ap->a_uio;
	struct apfsnode *apnode = VTOA(vp);
	struct apfsmount *amp = apnode->a_amp;
	j_extent_key_t key, found_key;
	j_phys_ext_val_t val;
	struct buf *bp;
	int error = 0;

	if (vp->v_type != VREG)
		return EISDIR;

	while (uio->uio_resid > 0 && uio->uio_offset < apnode->a_ino.uncompressed_size) {
		key.obj_id_and_type = ((uint64_t)apnode->a_oid << 4) | APFS_TYPE_EXTENT;
		key.logical_addr = uio->uio_offset;

		error = apfs_btree_search(amp, amp->am_sb.apfs_root_tree_oid, &key, &val, &found_key);
		if (error) {
			/* Hole */
			size_t n = MIN(uio->uio_resid, amp->am_block_size - (uio->uio_offset % amp->am_block_size));
			error = uiomove_zeros(n, uio);
			if (error) break;
			continue;
		}

		uint64_t extent_len = val.len_and_flags & EXTENT_LEN_MASK;
		if (uio->uio_offset < found_key.logical_addr || uio->uio_offset >= found_key.logical_addr + extent_len) {
			/* Offset not covered by this extent, must be a hole */
			size_t n = MIN(uio->uio_resid, amp->am_block_size - (uio->uio_offset % amp->am_block_size));
			error = uiomove_zeros(n, uio);
			if (error) break;
			continue;
		}

		/* Read from extent */
		uint64_t block_off = uio->uio_offset - found_key.logical_addr;
		uint64_t phys_block = val.phys_addr + (block_off / amp->am_block_size);
		size_t off_in_block = block_off % amp->am_block_size;
		size_t n = MIN(uio->uio_resid, amp->am_block_size - off_in_block);
		n = MIN(n, found_key.logical_addr + extent_len - uio->uio_offset);

		error = bread(amp->am_devvp, phys_block, amp->am_block_size, 0, &bp);
		if (error) break;

		error = uiomove((uint8_t *)bp->b_data + off_in_block, n, uio);
		brelse(bp, 0);
		if (error) break;
	}

	return error;
}

int
apfs_vop_write(void *v)
{
	struct vop_write_args *ap = v;
	struct vnode *vp = ap->a_vp;
	struct uio *uio = ap->a_uio;
	struct apfsnode *apnode = VTOA(vp);
	
	(void)uio;
	(void)apnode;

	/* TODO:
	 * 1. Allocate blocks for data (apfs_alloc_block).
	 * 2. Create EXTENT records.
	 * 3. Update inode size.
	 * 4. COW the Root Tree.
	 */
	
	return EOPNOTSUPP;
}

int
apfs_vop_fsync(void *v)
{
	/* TODO: Flush transactions and write new Container Superblock (COW) */
	return 0;
}

int
apfs_vop_remove(void *v)
{
	return EOPNOTSUPP;
}

int
apfs_vop_mkdir(void *v)
{
	return EOPNOTSUPP;
}

int
apfs_vop_rmdir(void *v)
{
	return EOPNOTSUPP;
}

int
apfs_vop_readdir(void *v)
{
	struct vop_readdir_args *ap = v;
	struct vnode *vp = ap->a_vp;
	struct uio *uio = ap->a_uio;
	struct apfsnode *apnode = VTOA(vp);
	struct dirent de;
	int error = 0;

	if (vp->v_type != VDIR)
		return ENOTDIR;

	while (uio->uio_resid > 0) {
		memset(&de, 0, sizeof(de));
		if (uio->uio_offset == 0) {
			de.d_fileno = apnode->a_oid;
			de.d_type = DT_DIR;
			de.d_namlen = 1;
			strlcpy(de.d_name, ".", sizeof(de.d_name));
		} else if (uio->uio_offset == 1) {
			de.d_fileno = apnode->a_ino.parent_id;
			de.d_type = DT_DIR;
			de.d_namlen = 2;
			strlcpy(de.d_name, "..", sizeof(de.d_name));
		} else {
			break;
		}

		de.d_reclen = _DIRENT_SIZE(&de);
		if (uio->uio_resid < de.d_reclen)
			break;

		error = uiomove(&de, de.d_reclen, uio);
		if (error)
			break;

		uio->uio_offset++;
	}

	return error;
}

int
apfs_vop_inactive(void *v)
{
	struct vop_inactive_v2_args *ap = v;
	VOP_UNLOCK(ap->a_vp);
	return 0;
}

int
apfs_vop_reclaim(void *v)
{
	struct vop_reclaim_v2_args *ap = v;
	struct vnode *vp = ap->a_vp;
	struct apfsnode *apnode = vp->v_data;

	genfs_node_destroy(vp);
	if (apnode)
		kmem_free(apnode, sizeof(*apnode));
	vp->v_data = NULL;

	return 0;
}

int
apfs_vop_strategy(void *v)
{
	return EOPNOTSUPP;
}

int
apfs_vop_bmap(void *v)
{
	return EOPNOTSUPP;
}

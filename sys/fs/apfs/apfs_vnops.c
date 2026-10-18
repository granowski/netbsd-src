/*	$NetBSD$	*/

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/buf.h>
#include <sys/dirent.h>
#include <sys/kmem.h>

#include <fs/apfs/apfs.h>

/* Global vnode operation descriptors */
int (**apfs_vnodeop_p)(void *);
const struct vnodeopv_entry_desc apfs_vnodeop_entries[] = {
	{ &vop_default_desc, vn_default_error },
	{ &vop_parsepath_desc, genfs_parsepath },
	{ &vop_lookup_desc, apfs_vop_lookup },
	{ &vop_open_desc, apfs_vop_open },
	{ &vop_close_desc, apfs_vop_close },
	{ &vop_access_desc, apfs_vop_access },
	{ &vop_getattr_desc, apfs_vop_getattr },
	{ &vop_read_desc, apfs_vop_read },
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
	
	/* TODO: Search Volume Root Tree for DREC record */
	
	return ENOENT;
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

	return vaccess(vp->v_type, apnode->a_ino.mode, apnode->a_ino.owner,
	    apnode->a_ino.group, ap->a_mode, ap->a_cred);
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
apfs_vop_read(void *v)
{
	struct vop_read_args *ap = v;
	struct vnode *vp = ap->a_vp;
	struct uio *uio = ap->a_uio;

	/* TODO: Implement extent mapping and bread() */
	
	return EOPNOTSUPP;
}

int
apfs_vop_readdir(void *v)
{
	return EOPNOTSUPP;
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

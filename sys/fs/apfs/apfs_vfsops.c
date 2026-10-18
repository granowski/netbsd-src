/*	$NetBSD$	*/

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/namei.h>
#include <sys/proc.h>
#include <sys/kernel.h>
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/buf.h>
#include <sys/device.h>
#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/module.h>
#include <sys/fcntl.h>
#include <uvm/uvm_extern.h>

#include <miscfs/genfs/genfs.h>
#include <miscfs/specfs/specdev.h>

#include <fs/apfs/apfs.h>

MODULE(MODULE_CLASS_VFS, apfs, NULL);

struct vfsops apfs_vfsops = {
	.vfs_name = "apfs",
	.vfs_min_mount_data = sizeof (struct apfs_args),
	.vfs_mount = apfs_mount,
	.vfs_start = apfs_start,
	.vfs_unmount = apfs_unmount,
	.vfs_root = apfs_root,
	.vfs_quotactl = (void *)eopnotsupp,
	.vfs_statvfs = apfs_statvfs,
	.vfs_sync = apfs_sync,
	.vfs_vget = apfs_vget,
	.vfs_fhtovp = (void *)eopnotsupp,
	.vfs_vptofh = (void *)eopnotsupp,
	.vfs_init = apfs_init,
	.vfs_reinit = apfs_reinit,
	.vfs_done = apfs_done,
	.vfs_mountroot = apfs_mountroot,
	.vfs_snapshot = (void *)eopnotsupp,
	.vfs_extattrctl = vfs_stdextattrctl,
	.vfs_suspendctl = genfs_suspendctl,
	.vfs_renamelock_enter = genfs_renamelock_enter,
	.vfs_renamelock_exit = genfs_renamelock_exit,
	.vfs_fsync = (void *)nullop,
	.vfs_opv_descs = apfs_vnodeopv_descs
};

static int
apfs_modcmd(modcmd_t modcmd, void *arg)
{
	int error = 0;

	switch (modcmd) {
	case MODULE_CMD_INIT:
		error = vfs_attach(&apfs_vfsops);
		break;
	case MODULE_CMD_FINI:
		error = vfs_detach(&apfs_vfsops);
		break;
	default:
		error = ENOTTY;
		break;
	}

	return error;
}

int
apfs_mount(struct mount *mp, const char *path, void *data, size_t *data_len)
{
	struct lwp *l = curlwp;
	struct apfs_args *args = data;
	struct vnode *devvp;
	struct apfsmount *amp;
	struct buf *bp;
	nx_superblock_t *nx;
	int error, mode;
	dev_t dev;

	if (args == NULL)
		return EINVAL;
	if (*data_len < sizeof *args)
		return EINVAL;

	if (mp->mnt_flag & MNT_UPDATE)
		return EOPNOTSUPP;

	/* 1. Get the device vnode */
	error = namei_simple_user(args->fspec, NSM_FOLLOW_NOEMULROOT, &devvp);
	if (error)
		return error;

	if (devvp->v_type != VBLK) {
		vrele(devvp);
		return ENOTBLK;
	}

	dev = devvp->v_rdev;
	if (bdevsw_lookup(dev) == NULL) {
		vrele(devvp);
		return ENXIO;
	}

	/* 2. Open the device */
	mode = FREAD;
	if ((mp->mnt_flag & MNT_RDONLY) == 0)
		mode |= FWRITE;
	
	vn_lock(devvp, LK_EXCLUSIVE | LK_RETRY);
	error = VOP_OPEN(devvp, mode, l->l_cred);
	VOP_UNLOCK(devvp);
	if (error) {
		vrele(devvp);
		return error;
	}

	/* 3. Read Container Superblock (Block 0) */
	error = bread(devvp, 0, 4096, 0, &bp);
	if (error) {
		goto error_close;
	}

	nx = (nx_superblock_t *)bp->b_data;
	if (nx->nx_magic != NX_MAGIC) {
		brelse(bp, 0);
		error = EINVAL;
		goto error_close;
	}

	/* 4. Allocate and initialize apfsmount */
	amp = kmem_zalloc(sizeof(*amp), KM_SLEEP);
	amp->am_mountp = mp;
	amp->am_dev = dev;
	amp->am_devvp = devvp;
	amp->am_block_size = nx->nx_block_size;
	if (amp->am_block_size == 0) amp->am_block_size = 4096;
	memcpy(&amp->am_nx, nx, sizeof(*nx));
	mutex_init(&amp->am_lock, MUTEX_DEFAULT, IPL_NONE);

	brelse(bp, 0);

	/* 5. Find Volume Superblock */
	error = ENOENT;
	for (int i = 0; i < nx->nx_max_file_systems; i++) {
		if (nx->nx_fs_oid[i] != 0) {
			apfs_paddr_t sb_paddr;
			/* Look up volume superblock in container OMap */
			error = apfs_omap_lookup(amp, nx->nx_fs_oid[i], nx->nx_next_xid - 1, &sb_paddr);
			if (error == 0) {
				error = bread(devvp, sb_paddr, amp->am_block_size, 0, &bp);
				if (error == 0) {
					apfs_superblock_t *vsb = (apfs_superblock_t *)bp->b_data;
					if (vsb->apfs_magic == APFS_MAGIC) {
						memcpy(&amp->am_sb, vsb, sizeof(*vsb));
						brelse(bp, 0);
						error = 0;
						break;
					}
					brelse(bp, 0);
				}
			}
		}
	}

	if (error) {
		mutex_destroy(&amp->am_lock);
		kmem_free(amp, sizeof(*amp));
		goto error_close;
	}

	mp->mnt_data = amp;
	mp->mnt_stat.f_namemax = 255;
	mp->mnt_flag |= MNT_LOCAL;
	mp->mnt_flag |= MNT_RDONLY; /* Force Read-Only for now */
	vfs_getnewfsid(mp);

	error = set_statvfs_info(path, UIO_USERSPACE, args->fspec, UIO_USERSPACE,
	    mp->mnt_op->vfs_name, mp, l);
	if (error) {
		mutex_destroy(&amp->am_lock);
		kmem_free(amp, sizeof(*amp));
		mp->mnt_data = NULL;
		goto error_close;
	}

	return 0;

error_close:
	vn_lock(devvp, LK_EXCLUSIVE | LK_RETRY);
	VOP_CLOSE(devvp, mode, l->l_cred);
	VOP_UNLOCK(devvp);
	vrele(devvp);
	return error;
}

int
apfs_start(struct mount *mp, int flags)
{
	return 0;
}

int
apfs_unmount(struct mount *mp, int mntflags)
{
	struct apfsmount *amp = mp->mnt_data;
	struct lwp *l = curlwp;
	int error, flags = 0;

	if (mntflags & MNT_FORCE)
		flags |= FORCECLOSE;

	error = vflush(mp, NULLVP, flags);
	if (error)
		return error;

	vn_lock(amp->am_devvp, LK_EXCLUSIVE | LK_RETRY);
	VOP_CLOSE(amp->am_devvp, (mp->mnt_flag & MNT_RDONLY) ? FREAD : FREAD|FWRITE, l->l_cred);
	VOP_UNLOCK(amp->am_devvp);

	vrele(amp->am_devvp);
	mutex_destroy(&amp->am_lock);
	kmem_free(amp, sizeof(*amp));
	mp->mnt_data = NULL;

	return 0;
}

int
apfs_root(struct mount *mp, int lktype, struct vnode **vpp)
{
	/* Root directory OID in APFS is typically 1 */
	return VFS_VGET(mp, 1, lktype, vpp);
}

int
apfs_statvfs(struct mount *mp, struct statvfs *sbp)
{
	struct apfsmount *amp = mp->mnt_data;

	sbp->f_bsize = amp->am_block_size;
	sbp->f_frsize = amp->am_block_size;
	sbp->f_iosize = amp->am_block_size;
	sbp->f_blocks = amp->am_nx.nx_block_count;
	sbp->f_bfree = amp->am_sb.apfs_fs_reserve_block_count; /* Simplified */
	sbp->f_bavail = amp->am_sb.apfs_fs_reserve_block_count;
	sbp->f_bresvd = 0;
	sbp->f_files = amp->am_sb.apfs_num_files + amp->am_sb.apfs_num_directories;
	sbp->f_ffree = 0;
	sbp->f_favail = 0;
	sbp->f_fresvd = 0;
	copystatvfs_info(sbp, mp);

	return 0;
}

int
apfs_sync(struct mount *mp, int waitfor, kauth_cred_t cred)
{
	return 0;
}

int
apfs_vget(struct mount *mp, ino_t ino, int lktype, struct vnode **vpp)
{
	struct apfsmount *amp = mp->mnt_data;
	struct apfsnode *apnode;
	struct vnode *vp;
	j_key_t key;
	j_inode_val_t val;
	int error;

	/* 1. Check vnode cache */
	error = vcache_get(mp, &ino, sizeof(ino), &vp);
	if (error)
		return error;

	vn_lock(vp, lktype | LK_RETRY);
	if (vp->v_data != NULL) {
		*vpp = vp;
		return 0;
	}

	/* 2. Load inode from Root Tree */
	key.obj_id_and_type = ((uint64_t)ino << 4) | APFS_TYPE_INODE;
	error = apfs_btree_search(amp, amp->am_sb.apfs_root_tree_oid, &key, &val, NULL);
	if (error) {
		vgone(vp);
		return error;
	}

	/* 3. Initialize apfsnode */
	apnode = kmem_zalloc(sizeof(*apnode), KM_SLEEP);
	apnode->a_amp = amp;
	apnode->a_vnode = vp;
	apnode->a_oid = ino;
	memcpy(&apnode->a_ino, &val, sizeof(val));

	vp->v_data = apnode;
	
	switch (apnode->a_ino.mode & S_IFMT) {
	case S_IFDIR: vp->v_type = VDIR; break;
	case S_IFREG: vp->v_type = VREG; break;
	case S_IFLNK: vp->v_type = VLNK; break;
	case S_IFBLK: vp->v_type = VBLK; break;
	case S_IFCHR: vp->v_type = VCHR; break;
	case S_IFIFO: vp->v_type = VFIFO; break;
	case S_IFSOCK: vp->v_type = VSOCK; break;
	default: vp->v_type = VNON; break;
	}

	genfs_node_init(vp, &apfs_vnodeop_p);
	uvm_vnodeops.vop_put = genfs_putpages; /* Basic paging support */

	*vpp = vp;
	return 0;
}

void
apfs_init(void)
{
}

void
apfs_reinit(void)
{
}

void
apfs_done(void)
{
}

int
apfs_mountroot(void)
{
	return EOPNOTSUPP;
}

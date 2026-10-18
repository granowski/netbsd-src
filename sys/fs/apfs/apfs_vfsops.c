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
	.vfs_fsync = (void *)eopnotsupp,
	.vfs_opv_descs = apfs_vnodeopv_descs
};

static int
apfs_modcmd(header_t modcmd, void *arg)
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
	struct vnode *devvp;
	struct apfsmount *amp;
	struct buf *bp;
	nx_superblock_t *nx;
	int error;
	dev_t dev;

	/* 1. Get the device vnode */
	error = namei_simple_kernel(path, NSM_FOLLOW_NOEMULROOT, &devvp);
	if (error)
		return error;

	if (devvp->v_type != VBLK) {
		vn_lock(devvp, LK_EXCLUSIVE | LK_RETRY);
		VOP_UNLOCK(devvp);
		vrele(devvp);
		return ENOTBLK;
	}

	dev = devvp->v_rdev;

	/* 2. Read Container Superblock (Block 0) */
	error = bread(devvp, 0, 4096, 0, &bp);
	if (error) {
		vrele(devvp);
		return error;
	}

	nx = (nx_superblock_t *)bp->b_data;
	if (nx->nx_magic != NX_MAGIC) {
		brelse(bp, 0);
		vrele(devvp);
		return EINVAL;
	}

	/* 3. Allocate and initialize apfsmount */
	amp = kmem_zalloc(sizeof(*amp), KM_SLEEP);
	amp->am_mountp = mp;
	amp->am_dev = dev;
	amp->am_devvp = devvp;
	amp->am_block_size = nx->nx_block_size;
	memcpy(&amp->am_nx, nx, sizeof(*nx));

	brelse(bp, 0);

	mp->mnt_data = amp;
	mp->mnt_stat.f_namemax = 255;
	mp->mnt_flag |= MNT_LOCAL;
	vfs_getnewfsid(mp);

	error = set_statvfs_info(path, UIO_USERSPACE, "apfs", UIO_SYSSPACE,
	    mp->mnt_stat.f_mntonname, sizeof(mp->mnt_stat.f_mntonname), mp, l);

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
	int error, flags = 0;

	if (mntflags & MNT_FORCE)
		flags |= FORCECLOSE;

	error = vflush(mp, NULLVP, flags);
	if (error)
		return error;

	vrele(amp->am_devvp);
	kmem_free(amp, sizeof(*amp));
	mp->mnt_data = NULL;
	mp->mnt_flag &= ~MNT_LOCAL;

	return 0;
}

int
apfs_root(struct mount *mp, int lktype, struct vnode **vpp)
{
	/* TODO: Implement root vnode retrieval via apfs_vget */
	return EOPNOTSUPP;
}

int
apfs_statvfs(struct mount *mp, struct statvfs *sbp)
{
	struct apfsmount *amp = mp->mnt_data;

	sbp->f_bsize = amp->am_block_size;
	sbp->f_frsize = amp->am_block_size;
	sbp->f_iosize = amp->am_block_size;
	sbp->f_blocks = amp->am_nx.nx_block_count;
	/* ... fill in more fields from nx and apfs superblocks ... */

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
	/* TODO: Implement inode lookup in APFS B-Tree */
	return EOPNOTSUPP;
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

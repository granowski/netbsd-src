/*	$NetBSD$	*/

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/namei.h>
#include <sys/proc.h>
#include <sys/kernel.h>
#include <sys/vnode.h>
#define APFS_FLAG_READ_ONLY_CONTAINER_COMPATIBLE (1 << 10)
#define APFS_FLAG_READ_ONLY_VOLUME_COMPATIBLE (1 << 11)
#include <sys/buf.h>
#include <sys/device.h>
#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/module.h>
#include <sys/fcntl.h>
#include <sys/endian.h>
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

static int
apfs_load_integrity(struct apfsmount *amp)
{
	integrity_meta_phys_t *meta;
	struct buf *bp;
	apfs_paddr_t paddr;
	uint32_t apfs_version, hash_type, hash_size, hash_offset, flags;
	uint8_t calculated_hash[BTREE_NODE_HASH_SIZE_MAX];
	int error;

	amp->am_sealed = false;
	amp->am_hash_type = 0;
	amp->am_hash_size = 0;
	explicit_memset(amp->am_root_hash, 0, sizeof(amp->am_root_hash));
	if ((le64toh(amp->am_sb.apfs_incompatible_features) &
	    APFS_INCOMPAT_SEALED_VOLUME) == 0)
		return 0;

	if (le16toh(amp->am_sb.apfs_role) != APFS_VOL_ROLE_SYSTEM ||
	    le64toh(amp->am_sb.apfs_integrity_meta_oid) == 0 ||
	    le64toh(amp->am_sb.apfs_fext_tree_oid) == 0)
		return EINVAL;

	error = apfs_omap_lookup(amp,
	    le64toh(amp->am_sb.apfs_omap_oid),
	    le64toh(amp->am_sb.apfs_integrity_meta_oid),
	    amp->am_checkpoint_xid, &paddr);
	if (error != 0)
		return error;
	error = apfs_bread(amp, paddr, &bp);
	if (error != 0)
		return error;

	meta = (integrity_meta_phys_t *)bp->b_data;
	if (!apfs_checksum_valid(amp, meta) ||
	    le64toh(meta->im_o.o_oid) !=
	    le64toh(amp->am_sb.apfs_integrity_meta_oid) ||
	    (le32toh(meta->im_o.o_type) & OBJECT_TYPE_MASK) !=
	    OBJECT_TYPE_INTEGRITY_META) {
		brelse(bp, 0);
		return EINVAL;
	}

	apfs_version = le32toh(meta->im_version);
	flags = le32toh(meta->im_flags);
	hash_type = le32toh(meta->im_hash_type);
	hash_offset = le32toh(meta->im_root_hash_offset);
	switch (hash_type) {
	case APFS_HASH_SHA256:
	case APFS_HASH_SHA512_256:
		hash_size = 32;
		break;
	case APFS_HASH_SHA384:
		hash_size = 48;
		break;
	case APFS_HASH_SHA512:
		hash_size = 64;
		break;
	default:
		brelse(bp, 0);
		return EOPNOTSUPP;
	}
	if (flags & APFS_SEAL_BROKEN) {
		brelse(bp, 0);
		return EAUTH;
	}
	if ((apfs_version != INTEGRITY_META_VERSION_1 &&
	    apfs_version != INTEGRITY_META_VERSION_2) ||
	    hash_offset < sizeof(*meta) ||
	    hash_offset > amp->am_block_size ||
	    hash_size > amp->am_block_size - hash_offset) {
		brelse(bp, 0);
		return EINVAL;
	}

	amp->am_hash_type = hash_type;
	amp->am_hash_size = hash_size;
	memcpy(amp->am_root_hash, (uint8_t *)meta + hash_offset, hash_size);
	amp->am_sealed = true;
	brelse(bp, 0);

	/* Ensure the selected hash algorithm is available before tree traversal. */
	error = apfs_hash_data(amp, "", 0, calculated_hash);
	explicit_memset(calculated_hash, 0, sizeof(calculated_hash));
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
	uint32_t block_size, max_file_systems;
	bool found_file_system;
	uint64_t stored_checksum;
	dev_t dev;

	if (args == NULL) {
		printf("apfs_mount: args is NULL\n");
		return EINVAL;
	}
	if (*data_len < sizeof *args) {
		printf("apfs_mount: data_len too small (%zu < %zu)\n", *data_len, sizeof *args);
		return EINVAL;
	}

	if (mp->mnt_flag & MNT_RDONLY) {
		/* Check for APFS read-only flags */
		if (mp->mnt_flag & APFS_FLAG_READ_ONLY_CONTAINER_COMPATIBLE) {
			/* Container is read-only, all writes fail */
			return EROFS;
		}
		if (mp->mnt_flag & APFS_FLAG_READ_ONLY_VOLUME_COMPATIBLE) {
			/* Volume is read-only, all writes fail */
			return EROFS;
		}
		/* Fall through to standard VFS checks */
	}

	/* 1. Get the device vnode */
	error = namei_simple_user(args->fspec, NSM_FOLLOW_NOEMULROOT, &devvp);
	if (error) {
		printf("apfs_mount: cannot resolve device %s: error %d\n",
		    args->fspec, error);
		return error;
	}

	if (devvp->v_type != VBLK) {
		printf("apfs_mount: %s is not a block device\n", args->fspec);
		vrele(devvp);
		return ENOTBLK;
	}

	dev = devvp->v_rdev;
	if (bdevsw_lookup(dev) == NULL) {
		printf("apfs_mount: no block device driver for %s\n", args->fspec);
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
		printf("apfs_mount: cannot open %s: error %d\n",
		    args->fspec, error);
		vrele(devvp);
		return error;
	}

	/* 3. Read block zero to discover the container block size. */
	error = bread(devvp, 0, 4096, 0, &bp);
	if (error) {
		printf("apfs_mount: cannot read container superblock: error %d\n",
		    error);
		goto error_close;
	}

	nx = (nx_superblock_t *)bp->b_data;
	if (le32toh(nx->nx_magic) != NX_MAGIC) {
		printf("apfs_mount: magic mismatch: expected 0x%x, got 0x%x (raw 0x%x)\n", 
		    NX_MAGIC, le32toh(nx->nx_magic), nx->nx_magic);
		brelse(bp, 0);
		error = EINVAL;
		goto error_close;
	}

	if ((le32toh(nx->nx_o.o_type) & OBJECT_TYPE_MASK) != OBJ_CONTAINER_SUPERBLOCK) {
		printf("apfs_mount: not a container superblock (type 0x%x, raw 0x%x)\n", 
		    le32toh(nx->nx_o.o_type), nx->nx_o.o_type);
		brelse(bp, 0);
		error = EINVAL;
		goto error_close;
	}

	block_size = le32toh(nx->nx_block_size);
	if (block_size < 4096 || block_size > 65536 ||
	    block_size % DEV_BSIZE != 0) {
		printf("apfs_mount: invalid container block size %u\n",
		    block_size);
		brelse(bp, 0);
		error = EINVAL;
		goto error_close;
	}

	brelse(bp, 0);
	bp = NULL;
	if (block_size != 4096) {
		error = bread(devvp, 0, block_size, 0, &bp);
		if (error != 0) {
			printf("apfs_mount: cannot read full container superblock: "
			    "error %d\n", error);
			goto error_close;
		}
		nx = (nx_superblock_t *)bp->b_data;
	}
	if (le32toh(nx->nx_magic) != NX_MAGIC ||
	    (le32toh(nx->nx_o.o_type) & OBJECT_TYPE_MASK) !=
	    OBJ_CONTAINER_SUPERBLOCK ||
	    le32toh(nx->nx_block_size) != block_size) {
		printf("apfs_mount: invalid full container superblock header\n");
		brelse(bp, 0);
		error = EINVAL;
		goto error_close;
	}
	memcpy(&stored_checksum, nx->nx_o.o_cksum, sizeof(stored_checksum));
	if (apfs_fletcher64(bp->b_data, block_size) !=
	    le64toh(stored_checksum)) {
		printf("apfs_mount: invalid container superblock checksum\n");
		brelse(bp, 0);
		error = EINVAL;
		goto error_close;
	}
	max_file_systems = le32toh(nx->nx_max_file_systems);
	if (max_file_systems > NX_MAX_FILE_SYSTEMS) {
		printf("apfs_mount: invalid filesystem count %u (maximum %u)\n",
		    max_file_systems, NX_MAX_FILE_SYSTEMS);
		brelse(bp, 0);
		error = EINVAL;
		goto error_close;
	}

	/* 4. Allocate and initialize apfsmount */
	amp = kmem_zalloc(sizeof(*amp), KM_SLEEP);
	amp->am_mountp = mp;
	amp->am_dev = dev;
	amp->am_devvp = devvp;
	amp->am_block_size = block_size;
	amp->am_block_shift = ffs(amp->am_block_size) - 1;
	memcpy(&amp->am_nx, nx, sizeof(*nx));
	mutex_init(&amp->am_lock, MUTEX_DEFAULT, IPL_NONE);

	brelse(bp, 0);

	/* Block zero only locates the checkpoint ring; it may be stale. */
	error = apfs_select_checkpoint(amp);
	if (error != 0) {
		printf("apfs_mount: could not find a valid container checkpoint: "
		    "error %d\n", error);
		mutex_destroy(&amp->am_lock);
		kmem_free(amp, sizeof(*amp));
		goto error_close;
	}
	max_file_systems = le32toh(amp->am_nx.nx_max_file_systems);
	printf("apfs_mount: selected checkpoint XID 0x%llx, OMap OID 0x%llx\n",
	    (unsigned long long)amp->am_checkpoint_xid,
	    (unsigned long long)le64toh(amp->am_nx.nx_omap_oid));

	/* 5. Find Volume Superblock */
	error = ENOENT;
	found_file_system = false;
	printf("apfs_mount: searching %u filesystem slots\n", max_file_systems);
	for (uint32_t i = 0; i < max_file_systems; i++) {
		uint64_t fs_oid = le64toh(amp->am_nx.nx_fs_oid[i]);
		apfs_paddr_t sb_paddr;
		apfs_superblock_t *vsb;

		if (fs_oid == 0)
			continue;
		found_file_system = true;

		error = apfs_omap_lookup(amp,
		    le64toh(amp->am_nx.nx_omap_oid), fs_oid,
		    amp->am_checkpoint_xid, &sb_paddr);
		if (error != 0) {
			printf("apfs_mount: OMap lookup failed for filesystem OID "
			    "0x%llx (slot %u): error %d\n",
			    (unsigned long long)fs_oid, i, error);
			continue;
		}

		printf("apfs_mount: filesystem OID 0x%llx maps to APFS block %lld\n",
		    (unsigned long long)fs_oid, (long long)sb_paddr);
		error = apfs_bread(amp, sb_paddr, &bp);
		if (error != 0) {
			printf("apfs_mount: cannot read volume superblock at APFS "
			    "block %lld: error %d\n", (long long)sb_paddr, error);
			continue;
		}

		vsb = (apfs_superblock_t *)bp->b_data;
		if (!apfs_checksum_valid(amp, bp->b_data) ||
		    le64toh(vsb->apfs_o.o_oid) != fs_oid ||
		    (le32toh(vsb->apfs_o.o_type) & OBJECT_TYPE_MASK) != OBJ_FS ||
		    le32toh(vsb->apfs_magic) != APFS_MAGIC) {
			printf("apfs_mount: invalid volume superblock at APFS block "
			    "%lld (oid 0x%llx type 0x%x magic 0x%x)\n",
			    (long long)sb_paddr,
			    (unsigned long long)le64toh(vsb->apfs_o.o_oid),
			    le32toh(vsb->apfs_o.o_type),
			    le32toh(vsb->apfs_magic));
			brelse(bp, 0);
			error = EINVAL;
			continue;
		}

		memcpy(&amp->am_sb, vsb, sizeof(*vsb));
		brelse(bp, 0);

		if ((le64toh(amp->am_sb.apfs_fs_flags) &
		    APFS_FS_UNENCRYPTED) == 0) {
			printf("apfs_mount: encrypted filesystem OID 0x%llx is "
			    "not supported yet\n",
			    (unsigned long long)fs_oid);
			error = EOPNOTSUPP;
			continue;
		}

		error = apfs_load_integrity(amp);
		if (error != 0) {
			printf("apfs_mount: cannot validate sealed-volume metadata "
			    "for filesystem OID 0x%llx: error %d\n",
			    (unsigned long long)fs_oid, error);
			continue;
		}

		apfs_paddr_t root_paddr;
		struct buf *root_bp;
		error = apfs_omap_lookup(amp,
		    le64toh(amp->am_sb.apfs_omap_oid),
		    le64toh(amp->am_sb.apfs_root_tree_oid),
		    amp->am_checkpoint_xid, &root_paddr);
		if (error != 0) {
			printf("apfs_mount: cannot resolve root tree OID 0x%llx: "
			    "error %d\n",
			    (unsigned long long)le64toh(
			    amp->am_sb.apfs_root_tree_oid), error);
			continue;
		}
		error = apfs_bread(amp, root_paddr, &root_bp);
		if (error != 0)
			continue;
		btree_node_phys_t *root = (btree_node_phys_t *)root_bp->b_data;
		uint16_t root_flags = le16toh(root->btn_flags);
		btree_info_t root_info;
		memcpy(&root_info, (uint8_t *)root + amp->am_block_size -
		    sizeof(root_info), sizeof(root_info));
		uint32_t tree_flags = le32toh(root_info.bt_flags);
		bool hashed = (tree_flags & BTREE_HASHED) != 0;
		uint8_t root_hash[BTREE_NODE_HASH_SIZE_MAX];
		error = 0;
		if (hashed) {
			error = (!amp->am_sealed ||
			    (tree_flags & (BTREE_HASHED | BTREE_NOHEADER)) !=
			    (BTREE_HASHED | BTREE_NOHEADER) ||
			    (root_flags & BTNODE_NOHEADER) == 0) ? EINVAL :
			    apfs_hash_data(amp, root, amp->am_block_size,
			    root_hash);
			if (error == 0 &&
			    memcmp(root_hash, amp->am_root_hash,
			    amp->am_hash_size) != 0)
				error = EAUTH;
		} else if (amp->am_sealed ||
		    (root_flags & BTNODE_NOHEADER) != 0 ||
		    !apfs_checksum_valid(amp, root_bp->b_data) ||
		    (le32toh(root->btn_o.o_type) & OBJECT_TYPE_MASK) !=
		    OBJ_BTREE) {
			error = EINVAL;
		}
		if (error != 0 ||
		    (le16toh(root->btn_flags) & BTNODE_ROOT) == 0 ||
		    (!hashed && le32toh(root->btn_o.o_subtype) != OBJ_FSTREE) ||
		    le32toh(root_info.bt_node_size) != amp->am_block_size ||
		    le64toh(root_info.bt_node_count) == 0) {
			if (error == 0)
				error = EINVAL;
			explicit_memset(root_hash, 0, sizeof(root_hash));
			brelse(root_bp, 0);
			printf("apfs_mount: invalid root file-system tree node at "
			    "APFS block %lld: error %d\n",
			    (long long)root_paddr, error);
			continue;
		}
		if ((tree_flags & BTREE_NOHEADER) != (hashed ?
		    BTREE_NOHEADER : 0) ||
		    (hashed && !amp->am_sealed) ||
		    (le32toh(root_info.bt_flags) &
		    (BTREE_PHYSICAL | BTREE_EPHEMERAL)) ==
		    (BTREE_PHYSICAL | BTREE_EPHEMERAL)) {
			brelse(root_bp, 0);
			printf("apfs_mount: unsupported root file-system tree "
			    "flags 0x%x\n", le32toh(root_info.bt_flags));
			error = EOPNOTSUPP;
			continue;
		}
		explicit_memset(root_hash, 0, sizeof(root_hash));
		brelse(root_bp, 0);
		error = 0;
		break;
	}

	if (!found_file_system)
		printf("apfs_mount: container has no filesystem OIDs in its "
		    "filesystem slots\n");

	if (error) {
		printf("apfs_mount: could not locate a valid volume superblock: "
		    "error %d\n", error);
		mutex_destroy(&amp->am_lock);
		kmem_free(amp, sizeof(*amp));
		goto error_close;
	}

	mp->mnt_data = amp;
	mp->mnt_stat.f_namemax = 255;
	mp->mnt_fs_bshift = amp->am_block_shift;
	mp->mnt_dev_bshift = DEV_BSHIFT;
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
	return VFS_VGET(mp, 2, lktype, vpp);
}

int
apfs_statvfs(struct mount *mp, struct statvfs *sbp)
{
	struct apfsmount *amp = mp->mnt_data;

	sbp->f_bsize = amp->am_block_size;
	sbp->f_frsize = amp->am_block_size;
	sbp->f_iosize = amp->am_block_size;
	sbp->f_blocks = le64toh(amp->am_nx.nx_block_count);
	sbp->f_bfree = le64toh(amp->am_sb.apfs_fs_reserve_block_count);
	sbp->f_bavail = le64toh(amp->am_sb.apfs_fs_reserve_block_count);
	sbp->f_bresvd = 0;
	sbp->f_files = le64toh(amp->am_sb.apfs_num_files) +
	    le64toh(amp->am_sb.apfs_num_directories);
	sbp->f_ffree = 0;
	sbp->f_favail = 0;
	sbp->f_fresvd = 0;
	copy_statvfs_info(sbp, mp);

	return 0;
}

int
apfs_sync(struct mount *mp, int waitfor, kauth_cred_t cred)
{
	return 0;
}

static const struct genfs_ops apfs_genfsops = {
	.gop_size = genfs_size,
};

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
	key.obj_id_and_type = htole64(((uint64_t)ino << 4) |
	    APFS_TYPE_INODE);
	error = apfs_btree_search(amp,
	    le64toh(amp->am_sb.apfs_omap_oid),
	    le64toh(amp->am_sb.apfs_root_tree_oid), &key, sizeof(key), &val,
	    sizeof(val), NULL, 0);
	if (error) {
		vgone(vp);
		vput(vp);
		return error;
	}

	/* 3. Initialize apfsnode */
	apnode = kmem_zalloc(sizeof(*apnode), KM_SLEEP);
	apnode->a_amp = amp;
	apnode->a_vnode = vp;
	apnode->a_oid = ino;
	memcpy(&apnode->a_ino, &val, sizeof(val));
	apnode->a_ino.parent_id = le64toh(apnode->a_ino.parent_id);
	apnode->a_ino.private_id = le64toh(apnode->a_ino.private_id);
	apnode->a_ino.create_time = le64toh(apnode->a_ino.create_time);
	apnode->a_ino.mod_time = le64toh(apnode->a_ino.mod_time);
	apnode->a_ino.change_time = le64toh(apnode->a_ino.change_time);
	apnode->a_ino.access_time = le64toh(apnode->a_ino.access_time);
	apnode->a_ino.internal_flags = le64toh(apnode->a_ino.internal_flags);
	apnode->a_ino.nchildren = le32toh(apnode->a_ino.nchildren);
	apnode->a_ino.default_protection_class =
	    le32toh(apnode->a_ino.default_protection_class);
	apnode->a_ino.write_generation_counter =
	    le32toh(apnode->a_ino.write_generation_counter);
	apnode->a_ino.bsd_flags = le32toh(apnode->a_ino.bsd_flags);
	apnode->a_ino.owner = le32toh(apnode->a_ino.owner);
	apnode->a_ino.group = le32toh(apnode->a_ino.group);
	apnode->a_ino.mode = le16toh(apnode->a_ino.mode);
	apnode->a_ino.uncompressed_size =
	    le64toh(apnode->a_ino.uncompressed_size);

	vp->v_tag = VT_NON; /* TODO: Add VT_APFS to NetBSD */
	vp->v_op = apfs_vnodeop_p;
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

	genfs_node_init(vp, &apfs_genfsops);
	uvm_vnp_setsize(vp, apnode->a_ino.uncompressed_size);

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

/*	$NetBSD$	*/

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/buf.h>
#include <sys/dirent.h>
#include <sys/kmem.h>
#include <sys/endian.h>

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
	{ &vop_pathconf_desc, genfs_pathconf },
	{ &vop_strategy_desc, apfs_vop_strategy },
	{ &vop_bmap_desc, apfs_vop_bmap },
	{ &vop_getpages_desc, genfs_getpages },
	{ &vop_putpages_desc, genfs_putpages },
	{ NULL, NULL }
};
const struct vnodeopv_desc apfs_vnodeop_opv_desc =
	{ &apfs_vnodeop_p, apfs_vnodeop_entries };

const struct vnodeopv_desc * const apfs_vnodeopv_descs[] = {
	&apfs_vnodeop_opv_desc,
	NULL,
};

static int
apfs_name_hash(const char *name, size_t len, bool case_insensitive,
    bool normalization_insensitive, uint32_t *hashp)
{
	const uint8_t *p = (const uint8_t *)name;
	uint32_t crc = 0xffffffff;

	while (len != 0) {
		uint32_t cp;
		size_t nbytes;

		if (p[0] < 0x80) {
			cp = p[0];
			nbytes = 1;
		} else if ((p[0] & 0xe0) == 0xc0) {
			cp = p[0] & 0x1f;
			nbytes = 2;
		} else if ((p[0] & 0xf0) == 0xe0) {
			cp = p[0] & 0x0f;
			nbytes = 3;
		} else if ((p[0] & 0xf8) == 0xf0) {
			cp = p[0] & 0x07;
			nbytes = 4;
		} else {
			return EILSEQ;
		}
		if (nbytes > len)
			return EILSEQ;
		for (size_t i = 1; i < nbytes; i++) {
			if ((p[i] & 0xc0) != 0x80)
				return EILSEQ;
			cp = (cp << 6) | (p[i] & 0x3f);
		}
		if ((nbytes == 2 && cp < 0x80) ||
		    (nbytes == 3 && cp < 0x800) ||
		    (nbytes == 4 && cp < 0x10000) ||
		    cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff))
			return EILSEQ;
		/* Unicode folding and NFD require tables not available here. */
		if (cp > 0x7f &&
		    (case_insensitive || normalization_insensitive))
			return EOPNOTSUPP;
		if (case_insensitive && cp >= 'A' && cp <= 'Z')
			cp += 'a' - 'A';

		for (size_t i = 0; i < sizeof(cp); i++) {
			crc ^= (cp >> (i * 8)) & 0xff;
			for (unsigned int bit = 0; bit < 8; bit++)
				crc = (crc >> 1) ^
				    (0x82f63b78U & -(crc & 1));
		}
		p += nbytes;
		len -= nbytes;
	}

	*hashp = crc & 0x003fffff;
	return 0;
}

int
apfs_vop_lookup(void *v)
{
	struct vop_lookup_v2_args *ap = v;
	struct vnode *dvp = ap->a_dvp;
	struct componentname *cnp = ap->a_cnp;
	struct apfsnode *dnode = VTOA(dvp);
	j_drec_key_t *key;
	j_drec_val_t val;
	uint64_t incompat_features;
	uint32_t name_hash;
	int error;

	printf("apfs_lookup: dir 0x%llx name '%.*s' len %zu\n",
	    (unsigned long long)dnode->a_oid, (int)cnp->cn_namelen,
	    cnp->cn_nameptr, cnp->cn_namelen);
	if (cnp->cn_nameptr[0] == '.') {
		if (cnp->cn_namelen == 1) {
			*ap->a_vpp = dvp;
			vref(dvp);
			printf("apfs_lookup: dot returns directory vnode %p\n",
			    dvp);
			return 0;
		}
		if (cnp->cn_namelen == 2 && cnp->cn_nameptr[1] == '.') {
			ino_t parent_ino = dnode->a_ino.parent_id;

			error = vcache_get(dvp->v_mount, &parent_ino,
			    sizeof(parent_ino), ap->a_vpp);
			printf("apfs_lookup: dotdot parent inode 0x%llx "
			    "vcache_get error %d vnode %p\n",
			    (unsigned long long)dnode->a_ino.parent_id, error,
			    error == 0 ? *ap->a_vpp : NULL);
			return error;
		}
	}

	if (cnp->cn_namelen >= DREC_NLEN_MASK)
		return ENAMETOOLONG;
	incompat_features =
	    le64toh(dnode->a_amp->am_sb.apfs_incompatible_features);
	error = apfs_name_hash(cnp->cn_nameptr, cnp->cn_namelen,
	    (incompat_features & APFS_INCOMPAT_CASE_INSENSITIVE) != 0,
	    (incompat_features & APFS_INCOMPAT_NORMALIZATION_INSENSITIVE) != 0,
	    &name_hash);
	if (error != 0) {
		printf("apfs_lookup: cannot hash name '%.*s': error %d\n",
		    (int)cnp->cn_namelen, cnp->cn_nameptr, error);
		return error;
	}
	printf("apfs_lookup: DREC hash 0x%x incompat features 0x%llx\n",
	    name_hash, (unsigned long long)incompat_features);

	key = kmem_alloc(sizeof(*key) + cnp->cn_namelen + 1, KM_SLEEP);
	key->obj_id_and_type = htole64(APFS_KEY(dnode->a_oid,
	    APFS_TYPE_DIR_REC));
	key->name_len_and_hash = htole32((name_hash << DREC_HASH_SHIFT) |
	    ((uint32_t)cnp->cn_namelen + 1));
	memcpy(key->name, cnp->cn_nameptr, cnp->cn_namelen);
	key->name[cnp->cn_namelen] = '\0';

	error = apfs_btree_search(dnode->a_amp,
	    le64toh(dnode->a_amp->am_sb.apfs_omap_oid),
	    le64toh(dnode->a_amp->am_sb.apfs_root_tree_oid), key,
	    sizeof(*key) + cnp->cn_namelen + 1, &val,
	    APFS_DREC_VAL_BASE_SIZE, NULL, 0);
	kmem_free(key, sizeof(*key) + cnp->cn_namelen + 1);

	if (error == 0) {
		printf("apfs_lookup: dir 0x%llx name '%.*s' resolved inode "
		    "0x%llx\n", (unsigned long long)dnode->a_oid,
		    (int)cnp->cn_namelen, cnp->cn_nameptr,
		    (unsigned long long)le64toh(val.file_id));
		ino_t ino = le64toh(val.file_id);

		error = vcache_get(dvp->v_mount, &ino, sizeof(ino), ap->a_vpp);
		printf("apfs_lookup: vcache_get inode 0x%llx returned error "
		    "%d vnode %p\n", (unsigned long long)ino, error,
		    error == 0 ? *ap->a_vpp : NULL);
		return error;
	}
	printf("apfs_lookup: dir 0x%llx name '%.*s' failed: error %d\n",
	    (unsigned long long)dnode->a_oid, (int)cnp->cn_namelen,
	    cnp->cn_nameptr, error);

	return error;
}

int
apfs_vop_create(void *v)
{
	struct vop_create_v3_args *ap = v;
	struct mount *mp = ap->a_dvp->v_mount;
	if (mp->mnt_flag & MNT_RDONLY)
		return EROFS;
	
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

	printf("apfs_getattr: begin inode 0x%llx vnode type %d mode 0%o\n",
	    (unsigned long long)apnode->a_oid, vp->v_type,
	    apnode->a_ino.mode);
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
	vap->va_bytes = vap->va_size;
	
	/* APFS timestamps are in nanoseconds since 1970-01-01 */
	vap->va_atime.tv_sec = apnode->a_ino.access_time / 1000000000;
	vap->va_atime.tv_nsec = apnode->a_ino.access_time % 1000000000;
	vap->va_mtime.tv_sec = apnode->a_ino.mod_time / 1000000000;
	vap->va_mtime.tv_nsec = apnode->a_ino.mod_time % 1000000000;
	vap->va_ctime.tv_sec = apnode->a_ino.change_time / 1000000000;
	vap->va_ctime.tv_nsec = apnode->a_ino.change_time % 1000000000;
	vap->va_birthtime.tv_sec = apnode->a_ino.create_time / 1000000000;
	vap->va_birthtime.tv_nsec = apnode->a_ino.create_time % 1000000000;

	printf("apfs_getattr: done inode 0x%llx type %d mode 0%o "
	    "size %llu nlink %llu uid %u gid %u\n",
	    (unsigned long long)apnode->a_oid, vap->va_type, vap->va_mode,
	    (unsigned long long)vap->va_size,
	    (unsigned long long)vap->va_nlink, (unsigned int)vap->va_uid,
	    (unsigned int)vap->va_gid);
	return 0;
}

int
apfs_vop_setattr(void *v)
{
	struct vop_setattr_args *ap = v;
	struct mount *mp = ap->a_vp->v_mount;
	if (mp->mnt_flag & MNT_RDONLY)
		return EROFS;
	
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
		key.obj_id_and_type = htole64(APFS_KEY(apnode->a_oid,
		    APFS_TYPE_EXTENT));
		key.logical_addr = htole64(uio->uio_offset);

		error = apfs_btree_search(amp,
		    le64toh(amp->am_sb.apfs_omap_oid),
		    le64toh(amp->am_sb.apfs_root_tree_oid), &key,
		    sizeof(key), &val, sizeof(val), &found_key,
		    sizeof(found_key));
		if (error) {
			/* Hole */
			size_t n = MIN(uio->uio_resid, amp->am_block_size - (uio->uio_offset % amp->am_block_size));
			char zero[512];
			memset(zero, 0, sizeof(zero));
			while (n > 0) {
				size_t m = MIN(n, sizeof(zero));
				error = uiomove(zero, m, uio);
				if (error) break;
				n -= m;
			}
			if (error) break;
			continue;
		}

		uint64_t extent_len = le64toh(val.len_and_flags) &
		    EXTENT_LEN_MASK;
		uint64_t extent_start = le64toh(found_key.logical_addr);
		uint64_t phys_addr = le64toh(val.phys_addr);
		if (uio->uio_offset < extent_start ||
		    uio->uio_offset >= extent_start + extent_len) {
			/* Offset not covered by this extent, must be a hole */
			size_t n = MIN(uio->uio_resid, amp->am_block_size - (uio->uio_offset % amp->am_block_size));
			char zero[512];
			memset(zero, 0, sizeof(zero));
			while (n > 0) {
				size_t m = MIN(n, sizeof(zero));
				error = uiomove(zero, m, uio);
				if (error) break;
				n -= m;
			}
			if (error) break;
			continue;
		}

		/* Read from extent */
		uint64_t block_off = uio->uio_offset - extent_start;
		uint64_t phys_block = phys_addr +
		    (block_off / amp->am_block_size);
		size_t off_in_block = block_off % amp->am_block_size;
		size_t n = MIN(uio->uio_resid, amp->am_block_size - off_in_block);
		n = MIN(n, extent_start + extent_len - uio->uio_offset);

		error = apfs_bread(amp, phys_block, &bp);
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
	struct mount *mp = ap->a_vp->v_mount;
	if (mp->mnt_flag & MNT_RDONLY)
		return EROFS;
	
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

struct apfs_readdir_ctx {
	struct uio *uio;
	oid_t dir_oid;
	int count;
	int skip;
};

static int
apfs_readdir_cb(void *arg, const void *k, size_t klen, const void *v, size_t vlen)
{
	struct apfs_readdir_ctx *ctx = arg;
	const j_drec_key_t *key = k;
	const j_drec_val_t *val = v;
	struct dirent de;
	uint32_t name_len;
	uint64_t key_word;
	off_t cookie;
	int error;

	if (klen < sizeof(key_word)) {
		printf("apfs_readdir_cb: short record key len %zu (min %zu)\n",
		    klen, sizeof(key_word));
		return EINVAL;
	}
	key_word = le64toh(key->obj_id_and_type);
	if ((key_word & OBJ_ID_MASK) != ctx->dir_oid ||
	    ((key_word & OBJ_TYPE_MASK) >> OBJ_TYPE_SHIFT) !=
	    APFS_TYPE_DIR_REC)
		return 0;
	if (klen < sizeof(*key) || vlen < APFS_DREC_VAL_BASE_SIZE) {
		printf("apfs_readdir_cb: short record key len %zu (min %zu) "
		    "value len %zu (min %zu)\n", klen, sizeof(*key), vlen,
		    (size_t)APFS_DREC_VAL_BASE_SIZE);
		return EINVAL;
	}
	printf("apfs_readdir_cb: key len %zu value len %zu skip %d "
	    "offset %lld resid %zu\n", klen, vlen, ctx->skip,
	    (long long)ctx->uio->uio_offset, ctx->uio->uio_resid);
	if (ctx->skip > 0) {
		ctx->skip--;
		ctx->uio->uio_offset++;
		return 0;
	}

	name_len = le32toh(key->name_len_and_hash) & DREC_NLEN_MASK;
	if (name_len == 0 || name_len > klen - sizeof(*key) ||
	    name_len >= sizeof(de.d_name)) {
		printf("apfs_readdir_cb: invalid name length %u key len %zu "
		    "raw name/hash 0x%x\n", name_len, klen,
		    le32toh(key->name_len_and_hash));
		return EINVAL;
	}
	if (key->name[name_len - 1] != '\0') {
		printf("apfs_readdir_cb: name is not NUL-terminated length %u\n",
		    name_len);
		return EINVAL;
	}
	printf("apfs_readdir_cb: record parent 0x%llx type 0x%llx "
	    "name length %u file id 0x%llx flags 0x%x\n",
	    (unsigned long long)(le64toh(key->obj_id_and_type) & OBJ_ID_MASK),
	    (unsigned long long)((le64toh(key->obj_id_and_type) &
	    OBJ_TYPE_MASK) >> OBJ_TYPE_SHIFT),
	    name_len, (unsigned long long)le64toh(val->file_id),
	    le16toh(val->flags));
	memset(&de, 0, sizeof(de));
	de.d_fileno = le64toh(val->file_id);
	de.d_namlen = name_len - 1;
	de.d_type = DT_UNKNOWN; /* Could be derived from val->flags */
	
	size_t name_to_copy = de.d_namlen;
	memcpy(de.d_name, key->name, name_to_copy);
	de.d_name[name_to_copy] = '\0';
	de.d_reclen = _DIRENT_SIZE(&de);

	if (ctx->uio->uio_resid < de.d_reclen) {
		printf("apfs_readdir_cb: buffer full for '%.*s' need %u "
		    "have %zu\n", (int)name_to_copy, de.d_name,
		    de.d_reclen, ctx->uio->uio_resid);
		return EJUSTRETURN; /* Stop iteration, but not an error */
	}

	printf("apfs_readdir_cb: emitting '%.*s' reclen %u offset %lld "
	    "resid %zu\n", (int)name_to_copy, de.d_name, de.d_reclen,
	    (long long)ctx->uio->uio_offset, ctx->uio->uio_resid);
	cookie = ctx->uio->uio_offset;
	error = uiomove(&de, de.d_reclen, ctx->uio);
	if (error) {
		printf("apfs_readdir_cb: uiomove for '%.*s' failed: %d\n",
		    (int)name_to_copy, de.d_name, error);
		return error;
	}

	ctx->count++;
	ctx->uio->uio_offset = cookie + 1;
	printf("apfs_readdir_cb: emitted '%.*s' new offset %lld "
	    "resid %zu\n", (int)name_to_copy, de.d_name,
	    (long long)ctx->uio->uio_offset, ctx->uio->uio_resid);
	return 0;
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
	if (uio->uio_offset < 0)
		return EINVAL;
	if (ap->a_eofflag != NULL)
		*ap->a_eofflag = 0;
	printf("apfs_readdir: dir 0x%llx offset %lld resid %zu "
	    "uio_rw %d\n", (unsigned long long)apnode->a_oid,
	    (long long)uio->uio_offset, uio->uio_resid, uio->uio_rw);

	/* 1. Handle . and .. */
	if (uio->uio_offset == 0) {
		memset(&de, 0, sizeof(de));
		de.d_fileno = apnode->a_oid;
		de.d_type = DT_DIR;
		de.d_namlen = 1;
		strlcpy(de.d_name, ".", sizeof(de.d_name));
		de.d_reclen = _DIRENT_SIZE(&de);
		if (uio->uio_resid < de.d_reclen) {
			printf("apfs_readdir: no space for dot entry need %u "
			    "have %zu\n", de.d_reclen, uio->uio_resid);
			return 0;
		}
		printf("apfs_readdir: emitting dot entry reclen %u\n",
		    de.d_reclen);
		error = uiomove(&de, de.d_reclen, uio);
		if (error) {
			printf("apfs_readdir: dot uiomove failed: %d\n", error);
			return error;
		}
		uio->uio_offset = 1;
		printf("apfs_readdir: emitted dot new offset %lld resid %zu\n",
		    (long long)uio->uio_offset, uio->uio_resid);
	}
	if (uio->uio_offset == 1) {
		memset(&de, 0, sizeof(de));
		de.d_fileno = apnode->a_ino.parent_id;
		de.d_type = DT_DIR;
		de.d_namlen = 2;
		strlcpy(de.d_name, "..", sizeof(de.d_name));
		de.d_reclen = _DIRENT_SIZE(&de);
		if (uio->uio_resid < de.d_reclen) {
			printf("apfs_readdir: no space for dotdot entry need %u "
			    "have %zu\n", de.d_reclen, uio->uio_resid);
			return 0;
		}
		printf("apfs_readdir: emitting dotdot entry reclen %u\n",
		    de.d_reclen);
		error = uiomove(&de, de.d_reclen, uio);
		if (error) {
			printf("apfs_readdir: dotdot uiomove failed: %d\n",
			    error);
			return error;
		}
		uio->uio_offset = 2;
		printf("apfs_readdir: emitted dotdot new offset %lld resid "
		    "%zu\n", (long long)uio->uio_offset, uio->uio_resid);
	}

	/* 2. Iterate B-tree for DRECs */
	struct apfs_readdir_ctx ctx;
	ctx.uio = uio;
	ctx.dir_oid = apnode->a_oid;
	ctx.count = 0;
	ctx.skip = uio->uio_offset > 2 ? uio->uio_offset - 2 : 0;

	j_drec_key_t start_key;
	memset(&start_key, 0, sizeof(start_key));
	start_key.obj_id_and_type = htole64(APFS_KEY(apnode->a_oid,
	    APFS_TYPE_DIR_REC));
	printf("apfs_readdir: starting tree iteration dir 0x%llx "
	    "offset %lld skip %d key 0x%llx\n",
	    (unsigned long long)apnode->a_oid, (long long)uio->uio_offset,
	    ctx.skip, (unsigned long long)le64toh(
	    start_key.obj_id_and_type));

	error = apfs_btree_iterate(apnode->a_amp,
	    le64toh(apnode->a_amp->am_sb.apfs_omap_oid),
	    le64toh(apnode->a_amp->am_sb.apfs_root_tree_oid), &start_key,
	    sizeof(start_key), apfs_readdir_cb, &ctx);

	if (error == EJUSTRETURN) error = 0;
	printf("apfs_readdir: dir 0x%llx done error %d emitted %d "
	    "offset %lld resid %zu\n", (unsigned long long)apnode->a_oid,
	    error, ctx.count, (long long)uio->uio_offset, uio->uio_resid);

	return error;
}

int
apfs_vop_inactive(void *v)
{
	struct vop_inactive_v2_args *ap = v;

	*ap->a_recycle = false;
	return 0;
}

int
apfs_vop_reclaim(void *v)
{
	struct vop_reclaim_v2_args *ap = v;
	struct vnode *vp = ap->a_vp;
	struct apfsnode *apnode = vp->v_data;

	VOP_UNLOCK(vp);
	if (apnode) {
		genfs_node_destroy(vp);
		kmem_free(apnode, sizeof(*apnode));
	}
	vp->v_data = NULL;

	return 0;
}

int
apfs_vop_strategy(void *v)
{
	struct vop_strategy_args *ap = v;
	struct buf *bp = ap->a_bp;
	struct vnode *vp = ap->a_vp;
	int error;

	if (vp->v_type == VBLK || vp->v_type == VCHR)
		panic("apfs_strategy: spec");

	if (bp->b_bcount == 0) {
		biodone(bp);
		return 0;
	}

	if (bp->b_blkno == bp->b_lblkno) {
		error = VOP_BMAP(vp, bp->b_lblkno, &vp, &bp->b_blkno, NULL);
		if (error) {
			bp->b_error = error;
			biodone(bp);
			return error;
		}
		if (bp->b_blkno == (daddr_t)-1) {
			clrbuf(bp);
			biodone(bp);
			return 0;
		}
	}

	return VOP_STRATEGY(vp, bp);
}

int
apfs_vop_bmap(void *v)
{
	struct vop_bmap_args *ap = v;
	struct vnode *vp = ap->a_vp;
	struct apfsnode *apnode = VTOA(vp);
	struct apfsmount *amp = apnode->a_amp;
	j_extent_key_t key, found_key;
	j_phys_ext_val_t val;
	int error;

	if (ap->a_vpp)
		*ap->a_vpp = amp->am_devvp;
	
	if (ap->a_bnp == NULL)
		return 0;

	key.obj_id_and_type = htole64(APFS_KEY(apnode->a_oid,
	    APFS_TYPE_EXTENT));
	key.logical_addr = htole64(
	    (uint64_t)ap->a_bn * amp->am_block_size);

	error = apfs_btree_search(amp,
	    le64toh(amp->am_sb.apfs_omap_oid),
	    le64toh(amp->am_sb.apfs_root_tree_oid), &key, sizeof(key),
	    &val, sizeof(val), &found_key, sizeof(found_key));
	if (error) {
		*ap->a_bnp = -1; /* Hole */
		return 0;
	}

	uint64_t extent_len = le64toh(val.len_and_flags) & EXTENT_LEN_MASK;
	uint64_t logical_addr = le64toh(key.logical_addr);
	uint64_t extent_start = le64toh(found_key.logical_addr);
	uint64_t phys_addr = le64toh(val.phys_addr);
	if (logical_addr < extent_start ||
	    logical_addr >= extent_start + extent_len) {
		*ap->a_bnp = -1;
		return 0;
	}

	*ap->a_bnp = (phys_addr + (logical_addr - extent_start) /
	    amp->am_block_size)
	    << (amp->am_block_shift - DEV_BSHIFT);
	
	if (ap->a_runp) {
		*ap->a_runp = (extent_len - (key.logical_addr - found_key.logical_addr)) / amp->am_block_size - 1;
	}

	return 0;
}

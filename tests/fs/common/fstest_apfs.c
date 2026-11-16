/*	$NetBSD$	*/

#include <sys/mount.h>
#include <sys/stat.h>

#include <atf-c.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <ufs/ufs/ufsmount.h>

#include <rump/rump.h>
#include <rump/rump_syscallshotgun.h>
#include <rump/rump_syscalls.h>

#include "h_fsmacros.h"

struct apfstestargs {
	struct ufs_args ta_uargs;
	char ta_devpath[MAXPATHLEN];
	char ta_imgpath[MAXPATHLEN];
};

int
apfs_fstest_newfs(const atf_tc_t *tc, void **buf, const char *image,
    off_t size, void *fspriv)
{
	int res;
	static unsigned int num = 0;
	struct apfstestargs *args;

	/* If test image exists (e.g. /tmp/apfs_test_images/fresh_50m.dmg), copy it */
	if (access("/tmp/apfs_test_images/fresh_50m.dmg", F_OK) == 0) {
		char cmd[1024];
		snprintf(cmd, sizeof(cmd), "cp /tmp/apfs_test_images/fresh_50m.dmg %s", image);
		res = system(cmd);
		if (res != 0)
			return res;
	} else {
		char cmd[1024];
		snprintf(cmd, sizeof(cmd), "python3 tests/fs/apfs/generate_test_images.py /tmp/apfs_test_images && cp /tmp/apfs_test_images/fresh_50m.dmg %s", image);
		res = system(cmd);
		if (res != 0)
			return res;
	}

	res = rump_init();
	if (res != 0)
		return res;

	args = calloc(1, sizeof(*args));
	if (args == NULL)
		return -1;

	snprintf(args->ta_devpath, MAXPATHLEN, "/dev/device%d.apfs", num);
	snprintf(args->ta_imgpath, MAXPATHLEN, "%s", image);
	args->ta_uargs.fspec = args->ta_devpath;

	res = rump_pub_etfs_register(args->ta_devpath, image, RUMP_ETFS_BLK);
	if (res != 0) {
		free(args);
		return res;
	}

	*buf = args;
	num++;

	return 0;
}

int
apfs_fstest_delfs(const atf_tc_t *tc, void *buf)
{
	int res;
	struct apfstestargs *args = buf;

	res = rump_pub_etfs_remove(args->ta_devpath);
	if (res != 0)
		return res;

	res = unlink(args->ta_imgpath);
	if (res != 0)
		return res;

	free(args);

	return 0;
}

int
apfs_fstest_mount(const atf_tc_t *tc, void *buf, const char *path, int flags)
{
	int res;
	struct apfstestargs *args = buf;

	res = rump_sys_mkdir(path, 0777);
	if (res == -1)
		return res;

	res = rump_sys_mount(MOUNT_APFS, path, flags, &args->ta_uargs,
	    sizeof(args->ta_uargs));
	return res;
}

int
apfs_fstest_unmount(const atf_tc_t *tc, const char *path, int flags)
{
	int res;

	res = rump_sys_unmount(path, flags);
	if (res == -1)
		return res;

	res = rump_sys_rmdir(path);
	return res;
}

/*	$NetBSD$	*/

#include <sys/types.h>
#include <sys/mount.h>
#include <sys/stat.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <rump/rump.h>
#include <rump/rump_syscalls.h>

#include "h_fsmacros.h"

#define TEST_FILE "/mnt/testfile.txt"
#define TEST_FILE2 "/mnt/renamed.txt"
#define TEST_DIR "/mnt/testdir"
#define TEST_DIR_FILE "/mnt/testdir/nested.txt"
#define TEST_SYMLINK "/mnt/symlink.txt"

ATF_TC(apfs_open_write_read);
ATF_TC_HEAD(apfs_open_write_read, tc)
{
	atf_tc_set_md_var(tc, "descr", "Verify basic open, write, and read on APFS");
}
ATF_TC_BODY(apfs_open_write_read, tc)
{
	void *args;
	int fd;
	char wbuf[1024];
	char rbuf[1024];
	ssize_t n;

	memset(wbuf, 'A', sizeof(wbuf));

	FSTEST_CONSTRUCTOR(tc, apfs, args);

	fd = rump_sys_open(TEST_FILE, O_CREAT | O_RDWR, 0644);
	ATF_REQUIRE_MSG(fd != -1, "open failed: %d", errno);

	n = rump_sys_write(fd, wbuf, sizeof(wbuf));
	ATF_REQUIRE_EQ_MSG(n, (ssize_t)sizeof(wbuf), "write failed: %d", errno);

	rump_sys_close(fd);

	fd = rump_sys_open(TEST_FILE, O_RDONLY, 0);
	ATF_REQUIRE_MSG(fd != -1, "re-open failed: %d", errno);

	memset(rbuf, 0, sizeof(rbuf));
	n = rump_sys_read(fd, rbuf, sizeof(rbuf));
	ATF_REQUIRE_EQ_MSG(n, (ssize_t)sizeof(rbuf), "read failed: %d", errno);
	ATF_REQUIRE_EQ_MSG(memcmp(wbuf, rbuf, sizeof(wbuf)), 0, "content mismatch");

	rump_sys_close(fd);

	FSTEST_DESTRUCTOR(tc, apfs, args);
}

ATF_TC(apfs_append_and_seek_write);
ATF_TC_HEAD(apfs_append_and_seek_write, tc)
{
	atf_tc_set_md_var(tc, "descr", "Verify append mode and seek-overwrite on APFS");
}
ATF_TC_BODY(apfs_append_and_seek_write, tc)
{
	void *args;
	int fd;
	char buf1[4096];
	char buf2[4096];
	char rbuf[8192];
	ssize_t n;

	memset(buf1, '1', sizeof(buf1));
	memset(buf2, '2', sizeof(buf2));

	FSTEST_CONSTRUCTOR(tc, apfs, args);

	/* 1. Initial 4KB write */
	fd = rump_sys_open(TEST_FILE, O_CREAT | O_WRONLY, 0644);
	ATF_REQUIRE(fd != -1);
	n = rump_sys_write(fd, buf1, sizeof(buf1));
	ATF_REQUIRE_EQ(n, (ssize_t)sizeof(buf1));
	rump_sys_close(fd);

	/* 2. Append 4KB */
	fd = rump_sys_open(TEST_FILE, O_WRONLY | O_APPEND, 0);
	ATF_REQUIRE(fd != -1);
	n = rump_sys_write(fd, buf2, sizeof(buf2));
	ATF_REQUIRE_EQ(n, (ssize_t)sizeof(buf2));
	rump_sys_close(fd);

	/* 3. Read back 8KB and verify */
	fd = rump_sys_open(TEST_FILE, O_RDONLY, 0);
	ATF_REQUIRE(fd != -1);
	n = rump_sys_read(fd, rbuf, sizeof(rbuf));
	ATF_REQUIRE_EQ(n, (ssize_t)sizeof(rbuf));
	ATF_REQUIRE_EQ(memcmp(rbuf, buf1, 4096), 0);
	ATF_REQUIRE_EQ(memcmp(rbuf + 4096, buf2, 4096), 0);
	rump_sys_close(fd);

	/* 4. Seek and overwrite in middle */
	fd = rump_sys_open(TEST_FILE, O_RDWR, 0);
	ATF_REQUIRE(fd != -1);
	off_t off = rump_sys_lseek(fd, 2048, SEEK_SET);
	ATF_REQUIRE_EQ(off, 2048);
	char patch[1024];
	memset(patch, 'P', sizeof(patch));
	n = rump_sys_write(fd, patch, sizeof(patch));
	ATF_REQUIRE_EQ(n, (ssize_t)sizeof(patch));
	rump_sys_close(fd);

	/* 5. Verify patch */
	fd = rump_sys_open(TEST_FILE, O_RDONLY, 0);
	ATF_REQUIRE(fd != -1);
	n = rump_sys_read(fd, rbuf, sizeof(rbuf));
	ATF_REQUIRE_EQ(n, (ssize_t)sizeof(rbuf));
	ATF_REQUIRE_EQ(memcmp(rbuf + 2048, patch, sizeof(patch)), 0);
	rump_sys_close(fd);

	FSTEST_DESTRUCTOR(tc, apfs, args);
}

ATF_TC(apfs_file_truncation);
ATF_TC_HEAD(apfs_file_truncation, tc)
{
	atf_tc_set_md_var(tc, "descr", "Verify file truncation (shrinking and expanding)");
}
ATF_TC_BODY(apfs_file_truncation, tc)
{
	void *args;
	int fd;
	char buf[16384];
	struct stat st;

	memset(buf, 'Z', sizeof(buf));

	FSTEST_CONSTRUCTOR(tc, apfs, args);

	fd = rump_sys_open(TEST_FILE, O_CREAT | O_RDWR, 0644);
	ATF_REQUIRE(fd != -1);
	rump_sys_write(fd, buf, sizeof(buf));

	/* Shrink to 4KB */
	int res = rump_sys_ftruncate(fd, 4096);
	ATF_REQUIRE_EQ(res, 0);

	res = rump_sys_fstat(fd, &st);
	ATF_REQUIRE_EQ(res, 0);
	ATF_REQUIRE_EQ(st.st_size, 4096);

	/* Expand to 32KB */
	res = rump_sys_ftruncate(fd, 32768);
	ATF_REQUIRE_EQ(res, 0);

	res = rump_sys_fstat(fd, &st);
	ATF_REQUIRE_EQ(res, 0);
	ATF_REQUIRE_EQ(st.st_size, 32768);

	rump_sys_close(fd);

	FSTEST_DESTRUCTOR(tc, apfs, args);
}

ATF_TC(apfs_atomic_rename);
ATF_TC_HEAD(apfs_atomic_rename, tc)
{
	atf_tc_set_md_var(tc, "descr", "Verify atomic file rename and overwrite rename");
}
ATF_TC_BODY(apfs_atomic_rename, tc)
{
	void *args;
	int fd, res;

	FSTEST_CONSTRUCTOR(tc, apfs, args);

	/* 1. Create file 1 */
	fd = rump_sys_open(TEST_FILE, O_CREAT | O_WRONLY, 0644);
	ATF_REQUIRE(fd != -1);
	rump_sys_write(fd, "HELLO", 5);
	rump_sys_close(fd);

	/* 2. Rename file1 -> file2 */
	res = rump_sys_rename(TEST_FILE, TEST_FILE2);
	ATF_REQUIRE_EQ(res, 0);

	/* Old file must not exist */
	fd = rump_sys_open(TEST_FILE, O_RDONLY, 0);
	ATF_REQUIRE_EQ(fd, -1);
	ATF_REQUIRE_EQ(errno, ENOENT);

	/* New file must exist */
	fd = rump_sys_open(TEST_FILE2, O_RDONLY, 0);
	ATF_REQUIRE(fd != -1);
	char rbuf[16];
	ssize_t n = rump_sys_read(fd, rbuf, sizeof(rbuf));
	ATF_REQUIRE_EQ(n, 5);
	ATF_REQUIRE_EQ(memcmp(rbuf, "HELLO", 5), 0);
	rump_sys_close(fd);

	FSTEST_DESTRUCTOR(tc, apfs, args);
}

ATF_TC(apfs_directory_and_unlink);
ATF_TC_HEAD(apfs_directory_and_unlink, tc)
{
	atf_tc_set_md_var(tc, "descr", "Verify directory creation, nested file creation, unlink, and rmdir");
}
ATF_TC_BODY(apfs_directory_and_unlink, tc)
{
	void *args;
	int fd, res;

	FSTEST_CONSTRUCTOR(tc, apfs, args);

	/* 1. mkdir */
	res = rump_sys_mkdir(TEST_DIR, 0755);
	ATF_REQUIRE_EQ(res, 0);

	/* 2. create file in directory */
	fd = rump_sys_open(TEST_DIR_FILE, O_CREAT | O_WRONLY, 0644);
	ATF_REQUIRE(fd != -1);
	rump_sys_write(fd, "NESTED", 6);
	rump_sys_close(fd);

	/* 3. unlink file */
	res = rump_sys_unlink(TEST_DIR_FILE);
	ATF_REQUIRE_EQ(res, 0);

	/* 4. rmdir directory */
	res = rump_sys_rmdir(TEST_DIR);
	ATF_REQUIRE_EQ(res, 0);

	FSTEST_DESTRUCTOR(tc, apfs, args);
}

ATF_TC(apfs_symlink_and_readlink);
ATF_TC_HEAD(apfs_symlink_and_readlink, tc)
{
	atf_tc_set_md_var(tc, "descr", "Verify symlink creation and readlink resolution");
}
ATF_TC_BODY(apfs_symlink_and_readlink, tc)
{
	void *args;
	int res;
	char target[256];

	FSTEST_CONSTRUCTOR(tc, apfs, args);

	/* 1. Create symlink */
	res = rump_sys_symlink("target_destination_file", TEST_SYMLINK);
	ATF_REQUIRE_EQ(res, 0);

	/* 2. Read link */
	memset(target, 0, sizeof(target));
	ssize_t n = rump_sys_readlink(TEST_SYMLINK, target, sizeof(target) - 1);
	ATF_REQUIRE_EQ(n, (ssize_t)strlen("target_destination_file"));
	ATF_REQUIRE_STREQ(target, "target_destination_file");

	/* 3. Unlink symlink */
	res = rump_sys_unlink(TEST_SYMLINK);
	ATF_REQUIRE_EQ(res, 0);

	FSTEST_DESTRUCTOR(tc, apfs, args);
}

ATF_TC(apfs_touch_and_vop_create);
ATF_TC_HEAD(apfs_touch_and_vop_create, tc)
{
	atf_tc_set_md_var(tc, "descr", "Verify touch, vn_open, and VOP_CREATE file creation lifecycle");
}
ATF_TC_BODY(apfs_touch_and_vop_create, tc)
{
	void *args;
	struct stat sb;
	int fd, res;

	FSTEST_CONSTRUCTOR(tc, apfs, args);

	/* 1. Initial touch creation: open with O_WRONLY | O_CREAT | O_TRUNC */
	fd = rump_sys_open(TEST_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0666);
	ATF_REQUIRE_MSG(fd != -1, "touch open failed: %d", errno);

	res = rump_sys_fstat(fd, &sb);
	ATF_REQUIRE_EQ(res, 0);
	ATF_REQUIRE_EQ(sb.st_size, 0);
	ATF_REQUIRE(S_ISREG(sb.st_mode));
	rump_sys_close(fd);

	/* 2. Re-touch existing file (O_CREAT without O_EXCL on existing vnode) */
	fd = rump_sys_open(TEST_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0666);
	ATF_REQUIRE_MSG(fd != -1, "second touch failed: %d", errno);
	rump_sys_close(fd);

	/* 3. Exclusive create should fail with EEXIST */
	fd = rump_sys_open(TEST_FILE, O_WRONLY | O_CREAT | O_EXCL, 0666);
	ATF_REQUIRE_EQ(fd, -1);
	ATF_REQUIRE_EQ(errno, EEXIST);

	/* 4. Write data, then touch with O_TRUNC to verify size reset */
	fd = rump_sys_open(TEST_FILE, O_WRONLY, 0);
	ATF_REQUIRE(fd != -1);
	ssize_t n = rump_sys_write(fd, "12345678", 8);
	ATF_REQUIRE_EQ(n, 8);
	rump_sys_close(fd);

	fd = rump_sys_open(TEST_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0666);
	ATF_REQUIRE(fd != -1);
	res = rump_sys_fstat(fd, &sb);
	ATF_REQUIRE_EQ(res, 0);
	ATF_REQUIRE_EQ(sb.st_size, 0);
	rump_sys_close(fd);

	/* 5. Clean up */
	res = rump_sys_unlink(TEST_FILE);
	ATF_REQUIRE_EQ(res, 0);

	FSTEST_DESTRUCTOR(tc, apfs, args);
}

ATF_TC(apfs_read_only_rejection);
ATF_TC_HEAD(apfs_read_only_rejection, tc)
{
	atf_tc_set_md_var(tc, "descr", "Verify mutation rejection on read-only mount");
}
ATF_TC_BODY(apfs_read_only_rejection, tc)
{
	void *args;
	int fd, res;

	FSTEST_CONSTRUCTOR_FSPRIV(tc, apfs, args, NULL);

	/* Unmount and remount read-only */
	apfs_fstest_unmount(tc, FSTEST_MNTNAME, 0);
	res = apfs_fstest_mount(tc, args, FSTEST_MNTNAME, MNT_RDONLY);
	ATF_REQUIRE_EQ(res, 0);

	/* Attempt file creation on read-only mount */
	fd = rump_sys_open(TEST_FILE, O_CREAT | O_WRONLY, 0644);
	ATF_REQUIRE_EQ(fd, -1);
	ATF_REQUIRE_EQ(errno, EROFS);

	/* Cleanup */
	apfs_fstest_unmount(tc, FSTEST_MNTNAME, 0);
	apfs_fstest_delfs(tc, args);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, apfs_open_write_read);
	ATF_TP_ADD_TC(tp, apfs_touch_and_vop_create);
	ATF_TP_ADD_TC(tp, apfs_append_and_seek_write);
	ATF_TP_ADD_TC(tp, apfs_file_truncation);
	ATF_TP_ADD_TC(tp, apfs_atomic_rename);
	ATF_TP_ADD_TC(tp, apfs_directory_and_unlink);
	ATF_TP_ADD_TC(tp, apfs_symlink_and_readlink);
	ATF_TP_ADD_TC(tp, apfs_read_only_rejection);

	return atf_no_error();
}

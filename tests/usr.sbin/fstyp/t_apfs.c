/*	$NetBSD$	*/

/*-
 * Copyright (c) 2026 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__RCSID("$NetBSD$");

#include <sys/param.h>
#include <sys/endian.h>

#include <atf-c.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fstyp.h"

#define	APFS_BLOCK_SIZE_4K	4096
#define	APFS_BLOCK_SIZE_64K	65536

static FILE *make_apfs_image(size_t, uint64_t);

void *
read_buf(FILE *fp, off_t off, size_t len)
{
	void *buf;

	if (fseeko(fp, off, SEEK_SET) != 0)
		return NULL;
	buf = malloc(len);
	if (buf == NULL)
		return NULL;
	if (fread(buf, len, 1, fp) != 1) {
		free(buf);
		return NULL;
	}
	return buf;
}

static FILE *
make_apfs_image(size_t block_size, uint64_t checksum)
{
	uint8_t *block;
	FILE *fp;

	block = calloc(1, block_size);
	ATF_REQUIRE(block != NULL);

	for (size_t off = 40; off < block_size; off++)
		block[off] = (uint8_t)(off * 13 + 7);

	*(uint64_t *)(void *)(block + 8) = htole64(1);
	*(uint64_t *)(void *)(block + 16) = htole64(UINT64_C(0x1122334455667788));
	*(uint32_t *)(void *)(block + 24) = htole32(1);
	memcpy(block + 32, "NXSB", 4);
	*(uint32_t *)(void *)(block + 36) = htole32((uint32_t)block_size);
	*(uint64_t *)(void *)block = htole64(checksum);

	fp = tmpfile();
	ATF_REQUIRE(fp != NULL);
	ATF_REQUIRE_EQ(fwrite(block, block_size, 1, fp), 1);
	free(block);
	rewind(fp);

	return fp;
}

ATF_TC(valid_4k_superblock);
ATF_TC_HEAD(valid_4k_superblock, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "recognize a valid APFS superblock with a 4 KiB checksum vector");
}
ATF_TC_BODY(valid_4k_superblock, tc)
{
	FILE *fp = make_apfs_image(APFS_BLOCK_SIZE_4K,
	    UINT64_C(0xdcdfadb371bd299c));

	ATF_REQUIRE_EQ(fstyp_apfs(fp, NULL, 0), 0);
	fclose(fp);
}

ATF_TC(valid_64k_superblock);
ATF_TC_HEAD(valid_64k_superblock, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "checksum the full 64 KiB APFS superblock");
}
ATF_TC_BODY(valid_64k_superblock, tc)
{
	FILE *fp = make_apfs_image(APFS_BLOCK_SIZE_64K,
	    UINT64_C(0x9f6c8262cd890acf));

	ATF_REQUIRE_EQ(fstyp_apfs(fp, NULL, 0), 0);
	fclose(fp);
}

ATF_TC(corrupted_superblock);
ATF_TC_HEAD(corrupted_superblock, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "reject an APFS superblock with a corrupted checksum-covered byte");
}
ATF_TC_BODY(corrupted_superblock, tc)
{
	FILE *fp = make_apfs_image(APFS_BLOCK_SIZE_4K,
	    UINT64_C(0xdcdfadb371bd299c));

	ATF_REQUIRE_EQ(fseek(fp, 100, SEEK_SET), 0);
	ATF_REQUIRE_EQ(fputc(0xff, fp), 0xff);
	rewind(fp);
	ATF_REQUIRE_EQ(fstyp_apfs(fp, NULL, 0), 1);
	fclose(fp);
}

ATF_TC(bad_superblock_header);
ATF_TC_HEAD(bad_superblock_header, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "reject non-APFS magic and an unsupported block size");
}
ATF_TC_BODY(bad_superblock_header, tc)
{
	FILE *fp;

	fp = make_apfs_image(APFS_BLOCK_SIZE_4K,
	    UINT64_C(0xdcdfadb371bd299c));
	ATF_REQUIRE_EQ(fseek(fp, 32, SEEK_SET), 0);
	ATF_REQUIRE_EQ(fwrite("NOPE", 4, 1, fp), 1);
	rewind(fp);
	ATF_REQUIRE_EQ(fstyp_apfs(fp, NULL, 0), 1);
	fclose(fp);

	fp = make_apfs_image(APFS_BLOCK_SIZE_4K,
	    UINT64_C(0xdcdfadb371bd299c));
	ATF_REQUIRE_EQ(fseek(fp, 36, SEEK_SET), 0);
	ATF_REQUIRE_EQ(fwrite("\x00\x08\x00\x00", 4, 1, fp), 1);
	rewind(fp);
	ATF_REQUIRE_EQ(fstyp_apfs(fp, NULL, 0), 1);
	fclose(fp);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, valid_4k_superblock);
	ATF_TP_ADD_TC(tp, valid_64k_superblock);
	ATF_TP_ADD_TC(tp, corrupted_superblock);
	ATF_TP_ADD_TC(tp, bad_superblock_header);

	return atf_no_error();
}

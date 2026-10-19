/*	$NetBSD: apfs.c,v 1.1 2019/12/27 11:15:06 tkusumi Exp $	*/
/*
 * Copyright (c) 2019 Conrad Meyer <cem@FreeBSD.org>.  All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include <sys/cdefs.h>
__RCSID("$NetBSD: apfs.c,v 1.1 2019/12/27 11:15:06 tkusumi Exp $");

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fstyp.h"

/**
 * calculate_fletcher64_checksum: Computes the 64-bit Fletcher checksum for the given data.
 * @param data Pointer to the data buffer.
 * @param len Length of the data buffer in bytes.
 * @return The 64-bit Fletcher checksum.
 */
uint64_t calculate_fletcher64_checksum(const void *data, size_t len)
{
    const uint8_t *buffer = (const uint8_t *)data;
    uint32_t sum1 = 0;
    uint32_t sum2 = 0;

    for (size_t i = 0; i < len; ++i) {
        // Sum1 accumulates the sums of bytes (b_i)
        sum1 = (sum1 + buffer[i]);
        // Sum2 accumulates the sums of the first sum (sum1)
        sum2 = (sum2 + sum1);
    }

    // Combine the two 32-bit sums into a single 64-bit result.
    return ((uint64_t)sum2 << 32) | sum1;
}

/**
 * checksum_validate_superblock: Validates the integrity of the Superblock using checksums.
 * @param csb The structure containing the Superblock data.
 * @return 0 on success, non-zero on failure.
 */
int checksum_validate_superblock(struct nx_superblock *csb)
{
    /*
     * Validation based on spec: The checksum covers all fields of the object metadata
     * (nx_o) EXCEPT for the space reserved for the checksum itself.
     * 1. Determine Payload Size: The checksum payload size is the offset of o_cksum
     *    within the nx_o object structure.
     */

    // 1. Calculate Payload Size: This is the offset of o_cksum within nx_o.
    const size_t payload_size = offsetof(struct nx_obj, o_cksum);

    // 2. Calculate Checksum: Use the Fletcher-64 algorithm on the payload region.
    uint64_t calculated_cksum = calculate_fletcher64_checksum(&csb->nx_o, payload_size);

    // 3. Compare: Extract the stored checksum and compare.
    uint64_t stored_cksum;
    // Copy the 8 bytes from the o_cksum field into our comparison variable.
    memcpy(&stored_cksum, &csb->nx_o.o_cksum, 8);

    if (calculated_cksum != stored_cksum) {
        fprintf(stderr, "APFS Checksum Error: Superblock integrity failure detected.\n");
        fprintf(stderr, "  Calculated Checksum: 0x%llX\n", (unsigned long long)calculated_cksum);
        fprintf(stderr, "  Stored Checksum:    0x%llX\n", (unsigned long long)stored_cksum);
        return EINVAL; // Indicates a checksum failure
    }

    return 0; // Success
}


/*
 * This really detects the container format, which might be best supported by
 * geom_part or a special GEOM class.
 *
 * https://developer.apple.com/support/downloads/Apple-File-System-Reference.pdf
 */
#define	NX_CKSUM_SZ		8

typedef uint64_t nx_oid_t;

typedef uint64_t nx_xid_t;

struct nx_obj {
    uint8_t		o_cksum[NX_CKSUM_SZ];	/* Fletcher 64 */
    nx_oid_t	o_oid;
    nx_xid_t	o_xid;
    uint32_t	o_type;
    uint32_t	o_subtype;
};

/* nx_obj::o_oid */
#define	OID_NX_SUPERBLOCK	1

/* nx_obj::o_type: */
#define	OBJECT_TYPE_MASK		0x0000ffff
#define	OBJECT_TYPE_NX_SUPERBLOCK	0x00000001
#define	OBJECT_TYPE_FLAGS_MASK		0xffff0000
#define	OBJ_STORAGETYPE_MASK		0xc0000000
#define	OBJECT_TYPE_FLAGS_DEFINED_MASK	0xf8000000
#define	OBJ_STORAGE_VIRTUAL		0x00000000
#define	OBJ_STORAGE_EPHEMERAL		0x80000000
#define	OBJ_STORAGE_PHYSICAL		0x40000000
#define	OBJ_NOHEADER			0x20000000
#define	OBJ_ENCRYPTED			0x10000000
#define	OBJ_NONPERSISTENT		0x08000000

struct nx_superblock {
    struct nx_obj	nx_o;
    char		nx_magic[4];
    /* ... other stuff that doesn't matter */
};

int
fstyp_apfs(FILE *fp, char *label, size_t size)
{
    struct nx_superblock *csb;
    int retval;

    retval = 1;
    csb = read_buf(fp, 0, sizeof(*csb));
    if (csb == NULL)
        goto fail;

    if (checksum_validate_superblock(csb) != 0)
        goto fail;

    retval = 0;

    /* No label support yet. */

fail:
    free(csb);
    return (retval);
}
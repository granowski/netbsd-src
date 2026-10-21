/* SPDX-License-Identifier: MIT */

#ifndef _FS_APFS_APFS_UNICODE_H_
#define _FS_APFS_APFS_UNICODE_H_

#include <sys/types.h>

#define APFS_UNICODE_NFD	0x01
#define APFS_UNICODE_CASEFOLD	0x02

/*
 * Return transformed Unicode scalar values allocated with kmem.  The caller
 * releases *outp with kmem_free(*outp, *outlenp * sizeof(**outp)).
 */
int	apfs_unicode_transform(const char *, size_t, unsigned int,
	    uint32_t **, size_t *);

#endif /* _FS_APFS_APFS_UNICODE_H_ */

/*	$NetBSD$	*/

#ifndef _SBIN_MOUNT_APFS_MOUNT_APFS_H_
#define _SBIN_MOUNT_APFS_MOUNT_APFS_H_

#include <fs/apfs/apfs.h>

int	mount_apfs(int, char **);
void	mount_apfs_parseargs(int, char **, struct apfs_args *, int *,
			    char *, char *);

#endif /* _SBIN_MOUNT_APFS_MOUNT_APFS_H_ */

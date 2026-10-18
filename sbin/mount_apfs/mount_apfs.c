/*	$NetBSD$	*/

#include <sys/cdefs.h>
#ifndef lint
__COPYRIGHT("@(#) Copyright (c) 2026 Junie.  All rights reserved.");
#endif /* not lint */

#include <sys/param.h>
#include <sys/mount.h>

#include <fs/apfs/apfs.h>

#include <err.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mntopts.h>

#include "mountprog.h"
#include "mount_apfs.h"

static const struct mntopt mopts[] = {
	MOPT_STDOPTS,
	MOPT_NULL,
};

__dead static void	usage(void);

#ifndef MOUNT_NOMAIN
int
main(int argc, char **argv)
{

	setprogname(argv[0]);
	return mount_apfs(argc, argv);
}
#endif

void
mount_apfs_parseargs(int argc, char *argv[],
	struct apfs_args *args, int *mntflags,
	char *canon_dev, char *canon_dir)
{
	mntoptparse_t optparse;
	int ch;

	memset(args, 0, sizeof(*args));
	*mntflags = 0;
	optind = optreset = 1;		/* Reset for parse of new argv. */
	while ((ch = getopt(argc, argv, "o:")) != -1)
		switch (ch) {
		case 'o':
			optparse = getmntopts(optarg, mopts, mntflags, 0);
			if (optparse == NULL)
				err(1, "getmntopts");
			freemntopts(optparse);
			break;
		case '?':
		default:
			usage();
		}
	argc -= optind;
	argv += optind;

	if (argc != 2)
		usage();

	pathadj(argv[0], canon_dev);
	pathadj(argv[1], canon_dir);
	args->fspec = canon_dev;	/* The name of the device file. */
}

int
mount_apfs(int argc, char *argv[])
{
	struct apfs_args args;
	char canon_dev[MAXPATHLEN], canon_dir[MAXPATHLEN];
	int mntflags;

	mount_apfs_parseargs(argc, argv, &args, &mntflags, canon_dev, canon_dir);

	if (mount(MOUNT_APFS, canon_dir, mntflags, &args, sizeof args) == -1)
		err(1, "%s on %s", args.fspec, canon_dir);

	exit(0);
}

static void
usage(void)
{
	fprintf(stderr, "usage: %s [-o options] special node\n", getprogname());
	exit(1);
}

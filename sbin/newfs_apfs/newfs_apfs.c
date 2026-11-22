/*	$NetBSD$	*/

#include <sys/cdefs.h>
#include <sys/param.h>

#include <stdio.h>
#include <err.h>
#include <stdlib.h>
#include <unistd.h>

static void usage(void) __dead;

int
main(int argc, char *argv[])
{
	int ch;
	const char *volname = "Untitled";

	while ((ch = getopt(argc, argv, "v:")) != -1) {
		switch (ch) {
		case 'v':
			volname = optarg;
			break;
		default:
			usage();
		}
	}
	
	argc -= optind;
	argv += optind;
	
	if (argc != 1)
		usage();

	errx(EXIT_FAILURE, "formatting APFS volume %s on %s is not implemented; "
	    "no data was written", volname, argv[0]);
}

static void
usage(void)
{
	fprintf(stderr, "usage: %s [-v volume_name] device\n", getprogname());
	exit(EXIT_FAILURE);
}

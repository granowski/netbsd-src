/*	$NetBSD$	*/

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/disklabel.h>
#include <sys/ioctl.h>
#include <sys/dkio.h>

#include <stdio.h>
#include <string.h>
#include <err.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <util.h>
#include <uuid.h>

#include <fs/apfs/apfs.h>

static void usage(void) __dead;

static uint64_t
apfs_fletcher64(const void *buf, size_t len)
{
	const uint32_t *data = buf;
	uint32_t s1 = 0, s2 = 0;
	size_t count = len / 4;

	/* Skip the first 8 bytes (checksum itself) */
	data += 2;
	count -= 2;

	for (size_t i = 0; i < count; i++) {
		s1 += data[i];
		s2 += s1;
	}

	return ((uint64_t)s2 << 32) | s1;
}

int
main(int argc, char *argv[])
{
	int ch;
	const char *volname = "Untitled";
	const char *device;
	int fd;
	struct stat st;
	nx_superblock_t nx;
	uint32_t status;
	uint64_t cksum;
	
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
	
	device = argv[0];
	
	fd = open(device, O_RDWR);
	if (fd == -1)
		err(EXIT_FAILURE, "Cannot open %s", device);
	
	if (fstat(fd, &st) == -1)
		err(EXIT_FAILURE, "Cannot stat %s", device);
	
	/* Initialize Container Superblock */
	memset(&nx, 0, sizeof(nx));
	nx.nx_o.o_oid = 1;
	nx.nx_o.o_xid = 1;
	nx.nx_o.o_type = OBJ_CONTAINER_SUPERBLOCK;
	nx.nx_o.o_subtype = 0;
	
	nx.nx_magic = NX_MAGIC;
	nx.nx_block_size = 4096;
	nx.nx_block_count = st.st_size / 4096;
	
	uuid_create(&nx.nx_uuid, &status);
	
	nx.nx_next_oid = 1024;
	nx.nx_next_xid = 2;
	
	/* Calculate checksum for nx */
	cksum = apfs_fletcher64(&nx, sizeof(nx));
	memcpy(nx.nx_o.o_cksum, &cksum, sizeof(cksum));
	
	/* TODO: Initialize descriptor and data areas for checkpoints */
	
	/* Write Superblock to Block 0 */
	if (pwrite(fd, &nx, sizeof(nx), 0) != sizeof(nx))
		err(EXIT_FAILURE, "Failed to write container superblock");
	
	printf("APFS container created on %s\n", device);
	printf("Volume Name: %s\n", volname);
	
	close(fd);
	return 0;
}

static void
usage(void)
{
	fprintf(stderr, "usage: %s [-v volume_name] device\n", getprogname());
	exit(EXIT_FAILURE);
}

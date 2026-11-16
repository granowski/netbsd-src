#	$NetBSD$

TESTSDIR=	${TESTSBASE}/fs/apfs
WARNS=		4

TESTS_C=	t_vfs_rw

VFSTESTDIR=	${.CURDIR}/../common
.PATH:		${VFSTESTDIR}
SRCS.t_vfs_rw=	t_vfs_rw.c fstest_apfs.c

LDADD+=-lrumpfs_apfs -lrumpfs_tmpfs
LDADD+=-lrumpdev_disk -lrumpdev
LDADD+=-lrumpvfs -lrump -lrumpuser -lrumpkern_sysproxy ${LIBRUMPBASE}
LDADD+=-lpthread

CPPFLAGS+=	-I${VFSTESTDIR}

.include <bsd.test.mk>

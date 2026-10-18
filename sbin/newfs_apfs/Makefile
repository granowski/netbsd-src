#	$NetBSD$

.include <bsd.own.mk>

PROG=	newfs_apfs
MAN=	newfs_apfs.8
SRCS=	newfs_apfs.c

LINKS=	${BINDIR}/newfs_apfs ${BINDIR}/mkfs.apfs
MLINKS=	newfs_apfs.8 mkfs.apfs.8

DPADD+=	${LIBUTIL}
LDADD+=	-lutil

CPPFLAGS+= -I${NETBSDSRCDIR}/sys

.include <bsd.prog.mk>

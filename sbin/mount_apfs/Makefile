#	$NetBSD$

.include <bsd.own.mk>

PROG=	mount_apfs
SRCS=	mount_apfs.c pathadj.c
MAN=	mount_apfs.8

MOUNT=	${NETBSDSRCDIR}/sbin/mount
CPPFLAGS+= -I${NETBSDSRCDIR}/sys -I${MOUNT}
.PATH:	${MOUNT}

DPADD+=${LIBUTIL}
LDADD+=-lutil

.include <bsd.prog.mk>

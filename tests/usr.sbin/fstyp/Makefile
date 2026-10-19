# $NetBSD$

.include <bsd.own.mk>

TESTSDIR=	${TESTSBASE}/usr.sbin/fstyp

TESTS_C+=	t_apfs
SRCS.t_apfs=	t_apfs.c ${NETBSDSRCDIR}/usr.sbin/fstyp/apfs.c
CPPFLAGS+=	-I${NETBSDSRCDIR}/usr.sbin/fstyp

.include <bsd.test.mk>

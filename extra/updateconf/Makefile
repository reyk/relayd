PROG=		updateconf

.PATH: ${.CURDIR}/../../relayd

SRCS=		parse.y
SRCS+=		updateconf.c

LDADD=		-lutil
DPADD=		${LIBUTIL}
CFLAGS+=	-Wall -I${.CURDIR} -I${.CURDIR}/../../relayd
CFLAGS+=	-Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=	-Wmissing-declarations
CFLAGS+=	-Wshadow -Wpointer-arith
CFLAGS+=	-Wsign-compare

CLEANFILES+=	y.tab.h
NOMAN=		1

run:
	@${.OBJDIR}/${PROG} -f ${.CURDIR}/relayd.conf

.include <bsd.prog.mk>

PROG=		relayd-updateconf

SRCS=		parse.y
SRCS+=		updateconf.c

BINDIR=		/usr/local/bin

LDADD=		-lutil
DPADD=		${LIBUTIL}
CFLAGS+=	-Wall -I${.CURDIR}
CFLAGS+=	-Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=	-Wmissing-declarations
CFLAGS+=	-Wshadow -Wpointer-arith
CFLAGS+=	-Wsign-compare

CLEANFILES+=	y.tab.h

.include <bsd.prog.mk>

run: .PHONY
	./relayd-updateconf -f ./relayd.conf

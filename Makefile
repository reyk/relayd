SUBDIR=		relayd relayctl regress
MAKE_FLAGS=	BINDIR=/usr/sbin SUDO=sudo

.include <bsd.subdir.mk>

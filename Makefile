SUBDIR=		relayd relayctl
MAKE_FLAGS=	BINDIR=/usr/sbin SUDO=sudo

.include <bsd.subdir.mk>

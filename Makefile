SUBDIR=		relayd relayctl
MAKE_FLAGS=	BINDIR=/usr/sbin SUDO=doas

.include <bsd.subdir.mk>

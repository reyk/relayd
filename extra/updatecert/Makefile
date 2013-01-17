PROG=		updatecert
LDADD=		-lcrypto -lssl
NOMAN=		yes
CLEANFILES+=	local.key ca.key ca.crt server.crt
SSLSERVER=	github.com

server.crt:
	echo -n | openssl s_client -connect $(SSLSERVER):443 | \
		sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > \
		server.crt

local.key:
	openssl genrsa -out local.key 2048

ca.crt:
	openssl req -x509 -days 365 \
		-newkey rsa:2048 -keyout ca.key \
		-out ca.crt

certs: $(PROG) local.key ca.crt server.crt
	@echo done

.include <bsd.prog.mk>

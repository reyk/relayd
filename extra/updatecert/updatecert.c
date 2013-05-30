/*	$git$	*/

/*
 * Copyright (c) 2013 Reyk Floeter <reyk@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <err.h>

#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>

int
password_cb(char *buf, int size, int rwflag, void *u)
{
	size_t	len;
	if (u == NULL) {
		bzero(buf, size);
		return (0);
	}
	if ((len = strlcpy(buf, u, size)) >= size)
		return (0);
	return (len);
}

EVP_PKEY *
get_key(const char *file, char *pass)
{
	FILE		*fp;
	EVP_PKEY	*key;

	if ((fp = fopen(file, "r")) == NULL)
		return (NULL);

	key = PEM_read_PrivateKey(fp, NULL, password_cb, pass);

	fclose(fp);
	return (key);
}

X509 *
get_cert(const char *file, char *pass)
{
	FILE		*fp;
	X509		*cert;

	if ((fp = fopen(file, "r")) == NULL)
		return (NULL);

	cert = PEM_read_X509(fp, NULL, password_cb, pass);

	fclose(fp);
	return (cert);
}

X509 *
updatecert(EVP_PKEY *key, EVP_PKEY *cakey, X509 *cacert, X509 *servercert)
{
	X509		*cert;
	static int	 serial = 0;
	X509_NAME	*name = NULL;

	if ((cert = X509_dup(servercert)) == NULL) {
		warn("X509");
		return (NULL);
	}

	X509_set_pubkey(cert, key);
	X509_set_issuer_name(cert, X509_get_subject_name(cacert));

	if (!X509_sign(cert, cakey, EVP_sha1())) {
		X509_free(cert);
		return (NULL);
	}

	return (cert);
}

int
main(int argc, char *argv[])
{
	EVP_PKEY	*key = NULL;
	EVP_PKEY	*cakey = NULL;
	X509		*cacert = NULL;
	X509		*servercert = NULL;
	X509		*cert = NULL;

	if (argc < 2)
		errx(1, "usage: %s CA-password", argv[0]);

	OpenSSL_add_all_algorithms();

	if ((key = get_key("local.key", NULL)) == NULL)
		err(1, "get local key");
	if ((cakey = get_key("ca.key", argv[1])) == NULL)
		err(1, "get ca key");
	if ((cacert = get_cert("ca.crt", NULL)) == NULL)
		err(1, "get ca cert");
	if ((servercert = get_cert("server.crt", NULL)) == NULL)
		err(1, "get server cert");

	X509_print_fp(stdout, servercert);
	printf("--------------\n");

	if ((cert = updatecert(key, cakey, cacert, servercert)) == NULL)
		err(1, "new cert");

	X509_print_fp(stdout, cert);

	X509_free(cert);
	X509_free(servercert);
	X509_free(cacert);
	EVP_PKEY_free(cakey);
	EVP_PKEY_free(key);

	return (0);	
}

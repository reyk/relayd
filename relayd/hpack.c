/*	$OpenBSD$	*/

/*
 * Copyright (c) 2019 Reyk Floeter <reyk@openbsd.org>
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
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <math.h>
#include <err.h>

#define HPACK_INTERNAL
#include "hpack.h"

static const struct hpack_index *
		 hpack_get_index(long);
static char	*hpack_decode_str(struct hbuf *, unsigned char);
static int	 hpack_decode_buf(struct hbuf *);

static int	 huffman_init(void);
static struct huffman_node *
		 huffman_new(void);
static void	 huffman_free(struct huffman_node *);

static struct hbuf *
		 hbuf_new(unsigned char *, size_t);
static void	 hbuf_free(struct hbuf *);
static int	 hbuf_writechar(struct hbuf *, unsigned char);
static int	 hbuf_writebuf(struct hbuf *, unsigned char *, size_t);
static unsigned char *
		 hbuf_release(struct hbuf *, size_t *);
static int	 hbuf_readchar(struct hbuf *, unsigned char *);
static int	 hbuf_readbuf(struct hbuf *, unsigned char **, size_t);
static int	 hbuf_advance(struct hbuf *, size_t);
static size_t	 hbuf_left(struct hbuf *);

static struct hpack	 hpack_global;

int
hpack_init(void)
{
	/* Initialize the huffman tree */
	if (huffman_init() == -1)
		return (-1);

	return (0);
}

struct hpack_context *
hpack_context_new()
{
	struct hpack_context	*hpack;

	if ((hpack = calloc(1, sizeof(*hpack))) == NULL)
		return (NULL);

	return (hpack);
}

void
hpack_context_free(struct hpack_context *hpack)
{
	if (hpack == NULL)
		return;
	free(hpack);
}

int
hpack_decode(unsigned char *buf, size_t len, struct hpack_context *hpack)
{
	struct hbuf		*hbuf = NULL;
	struct hpack_context	*ctx = NULL;
	int			 ret = -1;

	if (len == 0 || len > LONG_MAX)
		goto fail;

	if (hpack == NULL && (hpack = ctx = hpack_context_new()) == NULL)
		goto fail;

	if ((hbuf = hbuf_new(buf, len)) == NULL)
		goto fail;

	do {
		if (hpack_decode_buf(hbuf) == -1)
			goto fail;
	} while (hbuf_left(hbuf) > 0);

	ret = 0;
 fail:
	/* Free the local context (for single invocations) */
	hpack_context_free(ctx);
	hbuf_free(hbuf);

	return (ret);
}

static const struct hpack_index *
hpack_get_index(long i)
{
	struct hpack_index	*id;

	if (i < 1 || (size_t)i >= HPACK_STATIC_SIZE)
		return (NULL);

	id = &static_table[i - 1];
	if (id->hpi_id != i)
		errx(1, "corrupted HPACK static table %ld != %ld",
		    id->hpi_id, i);

	return (id);
}

static long
hpack_decode_int(struct hbuf *buf, unsigned char prefix)
{
	unsigned long	 i = 0, m;
	unsigned char	 b = 0;

	if (prefix > 8 || hbuf_left(buf) == 0)
		return (-1);

	if (hbuf_readchar(buf, &b) == -1 ||
	    hbuf_advance(buf, 1) == -1)
		return (-1);

	m = 0xff >> (8 - prefix);
	i = b & m;

	if (i >= m) {
		m = 0;
		do {
			if (i > LONG_MAX)
				return (-1);
			if (hbuf_readchar(buf, &b) == -1 ||
			    hbuf_advance(buf, 1) == -1)
				return (-1);
			i += (b & ~0x80) << m;
			m += 7;
		} while (b & 0x80);
	}

	return ((long)i);
}

static long
hpack_decode_index(struct hbuf *buf, unsigned char prefix,
    const struct hpack_index **idptr)
{
	const struct hpack_index	*id;
	long				 i;
	int				 hasvalue;

	if (idptr != NULL)
		*idptr = NULL;

	if ((i = hpack_decode_int(buf, prefix)) == -1)
		return (-1);

	if ((id = hpack_get_index(i)) == NULL)
		return (0);

	hasvalue = id->hpi_value == NULL ? 0 : 1;
	DPRINTF("%s: index: %ld (%s%s%s)", __func__,
	    i, id->hpi_name,
	    hasvalue ? ": " : "",
	    hasvalue ? id->hpi_value : "");

	if (idptr != NULL)
		*idptr = id;

	return (i);
}

static char *
hpack_decode_str(struct hbuf *buf, unsigned char prefix)
{
	long		 i;
	unsigned char	*ptr, c;
	char		*str;

	if (hbuf_readchar(buf, &c) == -1)
		return (NULL);
	if ((i = hpack_decode_int(buf, prefix)) == -1)
		return (NULL);
	if (hbuf_readbuf(buf, &ptr, (size_t)i) == -1 ||
	    hbuf_advance(buf, (size_t)i) == -1)
		return (NULL);
	if ((c & 0x80) == 0x80) {
		DPRINTF("%s: decoding huffman code", __func__);
		if ((str = huffman_decode_str(ptr, (size_t)i)) == NULL)
			return (NULL);
	} else {
		if ((str = calloc(1, (size_t)i + 1)) == NULL)
			return (NULL);
		memcpy(str, ptr, (size_t)i);
	}
	return (str);
}

static int
hpack_decode_literal(struct hbuf *buf, unsigned char prefix)
{
	const struct hpack_index	*id;
	long				 i;
	char				*str;

	if ((i = hpack_decode_index(buf, prefix, &id)) == -1)
		return (-1);

	if (i == 0) {
		if ((str = hpack_decode_str(buf, 7)) == NULL)
			return (-1);
		DPRINTF("%s: name: %s", __func__, str);
		free(str);
	}

	if ((str = hpack_decode_str(buf, 7)) == NULL)
		return (-1);
	DPRINTF("%s: value: %s", __func__, str);
	free(str);

	return (0);
}

static int
hpack_decode_buf(struct hbuf *buf)
{
	unsigned char			 c;
	long				 i;

	if (hbuf_readchar(buf, &c) == -1)
		return (-1);

	/* 6.1 Indexed Header Field Representation */
	if ((c & 0x80) == 0x80) {
		DPRINTF("%s: 0x%02x: 6.1 index", __func__, c);

		/* 7 bit index */
		if ((i = hpack_decode_index(buf, 7, NULL)) == -1)
			return (-1);
	}

	/* 6.2.1. Literal Header Field with Incremental Indexing */
	else if ((c & 0xc0) == 0x40) {
		DPRINTF("%s: 0x%02x: 6.2.1 literal indexed", __func__, c);

		/* 6 bit index */
		if (hpack_decode_literal(buf, 6) == -1)
			return (-1);
	}

	/* 6.2.2. Literal Header Field without Indexing */
	else if ((c & 0xf0) == 0x00) {
		DPRINTF("%s: 0x%02x: 6.2.2 literal", __func__, c);

		/* 4 bit index */
		if (hpack_decode_literal(buf, 4) == -1)
			return (-1);
	}

	/* 6.2.3. Literal Header Field Never Indexed */
	else if ((c & 0xf0) == 0x10) {
		DPRINTF("%s: 0x%02x: 6.2.3 literal never indexed", __func__, c);

		/* 4 bit index */
		if (hpack_decode_literal(buf, 4) == -1)
			return (-1);
	}

	/* 6.3. Dynamic Table Size Update */
	else if ((c & 0xe0) == 0x20) {
		DPRINTF("%s: 0x%02x: 6.3 dynamic table update", __func__, c);

		/* 5 bit index */
		if (hpack_decode_int(buf, 5) == -1)
			return (-1);
	}

	/* unknown index */
	else {
		DPRINTF("%s: 0x%02x: unknown index", __func__, c);
		return (-1);
	}

	return (0);
}

int
huffman_init(void)
{
	struct hpack_huffman	*hph;
	struct huffman_node	*root, *cur, *node;
	unsigned int		 i, j;

	if ((root = huffman_new()) == NULL)
		return (-1);

	for (i = 0; i < HPACK_HUFFMAN_SIZE; i++) {
		hph = &huffman_table[i];
		cur = root;

		for (j = hph->hph_length; j > 0; j--) {
			if ((hph->hph_code >> (j - 1)) & 1) {
				if (cur->hpn_one == NULL) {
					if ((node = huffman_new()) == NULL)
						goto fail;
					cur->hpn_one = node;
				}
				cur = cur->hpn_one;
			} else {
				if (cur->hpn_zero == NULL) {
					if ((node = huffman_new()) == NULL)
						goto fail;
					cur->hpn_zero = node;
				}
				cur = cur->hpn_zero;
			}
		}
		cur->hpn_sym = i;
	}

	hpack_global.hpack_huffman = root;
	return (0);
 fail:
	huffman_free(root);
	hpack_global.hpack_huffman = NULL;
	return (-1);
}

unsigned char *
huffman_decode(unsigned char *buf, size_t len, size_t *decoded_len)
{
	struct huffman_node	*node, *root;
	unsigned int		 i, j, code;
	struct hbuf		*hbuf = NULL;

	if ((root = node = hpack_global.hpack_huffman) == NULL)
		errx(1, "hpack not initialized");		

	if ((hbuf = hbuf_new(NULL, HUFFMAN_BUFSZ)) == NULL)
		return (NULL);

	for (i = 0; i < len; i++) {
		code = buf[i];

		for (j = 8; j > 0; j--) {
			if ((code >> (j - 1)) & 1)
				node = node->hpn_one;
			else
				node = node->hpn_zero;
			if (node->hpn_sym == -1)
				continue;
			if (hbuf_writechar(hbuf,
			    (unsigned char)node->hpn_sym) == -1) {
				DPRINTF("%s: failed to add '%c'", __func__,
				    node->hpn_sym);
				goto fail;
			}
			node = root;
		}
	}

	return (hbuf_release(hbuf, decoded_len));
 fail:
	*decoded_len = 0;
	hbuf_free(hbuf);
	return (NULL);
}

char *
huffman_decode_str(unsigned char *buf, size_t len)
{
	unsigned char	*data;
	char		*str;
	size_t		 data_len;

	if ((data = huffman_decode(buf, len, &data_len)) == NULL)
		return (NULL);

	/* Allocate with an extra NUL character */
	if ((str = recallocarray(data, data_len, data_len + 1, 1)) == NULL) {
		freezero(data, data_len);
		return (NULL);
	}

	/* Check if this is an actual string (no matter of the encoding) */
	if (strlen(str) != data_len) {
		freezero(str, data_len + 1);
		str = NULL;
	}

	return (str); 
}

static struct huffman_node *
huffman_new(void)
{
	struct huffman_node	*node;

	if ((node = calloc(1, sizeof(*node))) == NULL)
		return (NULL);
	node->hpn_sym = -1;

	return (node);
}

static void
huffman_free(struct huffman_node *root)
{
	if (root == NULL)
		return;
	huffman_free(root->hpn_zero);
	huffman_free(root->hpn_one);
	free(root);
}

static struct hbuf *
hbuf_new(unsigned char *data, size_t size)
{
	struct hbuf	*buf;

	if ((buf = calloc(1, sizeof(*buf))) == NULL)
		return (NULL);
	if (size == 0)
		size = HUFFMAN_BUFSZ;
	if ((buf->data = calloc(1, size)) == NULL) {
		free(buf);
		return (NULL);
	}
	if (data != NULL) {
		memcpy(buf->data, data, size);
		buf->wpos = size;
	}
	buf->size = buf->wbsz = size;
	return (buf);
}

static void
hbuf_free(struct hbuf *buf)
{
	if (buf == NULL)
		return;
	freezero(buf->data, buf->size);
	free(buf);
}

static int
hbuf_realloc(struct hbuf *buf, size_t len)
{
	unsigned char	*ptr;
	size_t		 newsize;

	/* Allocate a multiple of the initial write buffer size */
	newsize = (buf->size + len + (buf->wbsz - 1)) & ~(buf->wbsz - 1);

	DPRINTF("%s: size %zu -> %zu", __func__, buf->size, newsize);

	if ((ptr = recallocarray(buf->data, buf->size, newsize, 1)) == NULL)
		return (-1);
	buf->data = ptr;
	buf->size = newsize;

	return (0);
}

static int
hbuf_writechar(struct hbuf *buf, unsigned char c)
{
	return (hbuf_writebuf(buf, &c, 1));
}

static int
hbuf_writebuf(struct hbuf *buf, unsigned char *data, size_t len)
{
	if ((buf->wpos + len > buf->size) &&
	    hbuf_realloc(buf, len) == -1)
		return (-1);

	memcpy(buf->data + buf->wpos, data, len);
	buf->wpos += len;

	return (0);
}

static unsigned char *
hbuf_release(struct hbuf *buf, size_t *len)
{
	unsigned char	*data;
	*len = buf->wpos;
	data = buf->data;
	free(buf);
	return (data);
}

static int
hbuf_readchar(struct hbuf *buf, unsigned char *c)
{
	if (buf->rpos + 1 > buf->size)
		return (-1);
	*c = *(buf->data + buf->rpos);
	return (0);
}

static int
hbuf_readbuf(struct hbuf *buf, unsigned char **ptr, size_t len)
{
	if (buf->rpos + len > buf->size)
		return (-1);
	*ptr = buf->data + buf->rpos;
	return (0);
}

static int
hbuf_advance(struct hbuf *buf, size_t len)
{
	if (buf->rpos + len > buf->size)
		return (-1);
	buf->rpos += len;
	return (0);
}

static size_t
hbuf_left(struct hbuf *buf)
{
	if (buf->rpos >= buf->size)
		return (0);
	return (buf->size - buf->rpos);
}

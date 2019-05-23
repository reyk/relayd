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
		 hpack_table_getbyid(long, struct hpack_index *,
		    struct hpack_table *);
static const struct hpack_index *
		 hpack_table_getbyheader(struct hpack_header *,
		    struct hpack_index *, struct hpack_table *);
static int	 hpack_table_add(struct hpack_header *,
		    struct hpack_table *);
static int	 hpack_table_evict(long, long, struct hpack_table *);
static int	 hpack_table_setsize(long, struct hpack_table *);

static long	 hpack_decode_int(struct hbuf *, unsigned char);
static char	*hpack_decode_str(struct hbuf *, unsigned char);
static int	 hpack_decode_buf(struct hbuf *, struct hpack_table *);
static long	 hpack_decode_index(struct hbuf *, unsigned char,
		    const struct hpack_index **, struct hpack_table *);
static int	 hpack_decode_literal(struct hbuf *, unsigned char,
		    struct hpack_table *);
static int	 hpack_encode_int(struct hbuf *, long, unsigned char,
		    unsigned char);
static int	 hpack_encode_str(struct hbuf *, char *);

static int	 hpack_huffman_init(void);
static struct hpack_huffman_node *
		 hpack_huffman_new(void);
static void	 hpack_huffman_free(struct hpack_huffman_node *);

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
	if (hpack_huffman_init() == -1)
		return (-1);

	return (0);
}

struct hpack_header *
hpack_header_new(void)
{
	return (calloc(1, sizeof(struct hpack_header)));
}

struct hpack_header *
hpack_header_add(struct hpack_headerblock *hdrs, const char *name,
    const char *value, enum hpack_header_index index)
{
	struct hpack_header	*hdr;

	if ((hdr = hpack_header_new()) == NULL)
		return (NULL);
	hdr->hdr_name = strdup(name);
	hdr->hdr_value = strdup(value);
	hdr->hdr_index = index;
	if (hdr->hdr_name == NULL || hdr->hdr_value == NULL) {
		hpack_header_free(hdr);
		return (NULL);
	}
	TAILQ_INSERT_TAIL(hdrs, hdr, hdr_entry);

	return (hdr);
}

void
hpack_header_free(struct hpack_header *hdr)
{
	if (hdr == NULL)
		return;
	free(hdr->hdr_name);
	free(hdr->hdr_value);
	free(hdr);
}

struct hpack_headerblock *
hpack_headerblock_new(void)
{
	struct hpack_headerblock	*hdrs;
	if ((hdrs = calloc(1, sizeof(*hdrs))) == NULL)
		return (NULL);
	TAILQ_INIT(hdrs);
	return (hdrs);
}

void
hpack_headerblock_free(struct hpack_headerblock *hdrs)
{
	struct hpack_header	*hdr;

	if (hdrs == NULL)
		return;
	while ((hdr = TAILQ_FIRST(hdrs)) != NULL) {
		TAILQ_REMOVE(hdrs, hdr, hdr_entry);
		hpack_header_free(hdr);
	}
}

struct hpack_table *
hpack_table_new(size_t max_table_size)
{
	struct hpack_table	*hpack;

	if ((hpack = calloc(1, sizeof(*hpack))) == NULL)
		return (NULL);
	if ((hpack->htb_dynamic = hpack_headerblock_new()) == NULL) {
		free(hpack);
		return (NULL);
	}
	hpack->htb_max_table_size = hpack->htb_table_size =
	    max_table_size == 0 ? HPACK_MAX_TABLE_SIZE : max_table_size;

	return (hpack);
}

void
hpack_table_free(struct hpack_table *hpack)
{
	if (hpack == NULL)
		return;
	hpack_headerblock_free(hpack->htb_dynamic);
	free(hpack);
}

static const struct hpack_index *
hpack_table_getbyid(long index, struct hpack_index *idbuf,
    struct hpack_table *hpack)
{
	struct hpack_index		*id = NULL;
	struct hpack_header		*hdr;
	long				 dynidx = HPACK_STATIC_SIZE;

	if (index < 1 || index > dynidx + (long)hpack->htb_dynamic_size)
		return (NULL);

	if (index <= dynidx) {
		/* Static table */
		id = &static_table[index - 1];
		if (id->hpi_id != index)
			errx(1, "corrupted HPACK static table %ld != %ld",
			    id->hpi_id, index);
	} else {
		/* Dynamic table */
		TAILQ_FOREACH_REVERSE(hdr, hpack->htb_dynamic,
		    hpack_headerblock, hdr_entry) {
			dynidx++;
			if (dynidx == index) {
				idbuf->hpi_id = index;
				idbuf->hpi_name = hdr->hdr_name;
				idbuf->hpi_value = hdr->hdr_value;
				id = idbuf;
				break;
			}
		}
	}

	return (id);
}

static const struct hpack_index *
hpack_table_getbyheader(struct hpack_header *key, struct hpack_index *idbuf,
    struct hpack_table *hpack)
{
	struct hpack_index		*id = NULL, *firstid = NULL;
	struct hpack_header		*hdr;
	size_t				 i, dynidx = HPACK_STATIC_SIZE;

	if (key->hdr_name == NULL)
		return (NULL);

	/*
	 * Search the static and dynamic tables for a perfect match
	 * or the first match that only matches the name.
	 */

	/* Static table */
	for (i = 0; i < dynidx; i++) {
		id = &static_table[i];
		if (strcasecmp(id->hpi_name, key->hdr_name) != 0)
			continue;
		if (firstid == NULL) {
			memcpy(idbuf, id, sizeof(*id));
			idbuf->hpi_value = NULL;
			firstid = idbuf;
		}
		if ((id->hpi_value != NULL && key->hdr_value != NULL) &&
		    strcasecmp(id->hpi_value, key->hdr_value) == 0)
			return (id);
	}

	/* Dynamic table */
	TAILQ_FOREACH_REVERSE(hdr, hpack->htb_dynamic,
	    hpack_headerblock, hdr_entry) {
		dynidx++;
		if (strcasecmp(hdr->hdr_name, key->hdr_name) != 0)
			continue;
		if (firstid == NULL) {
			idbuf->hpi_id = dynidx;
			idbuf->hpi_name = hdr->hdr_name;
			idbuf->hpi_value = NULL;
			firstid = idbuf;
		}
		if ((hdr->hdr_value != NULL && key->hdr_value != NULL) &&
		    strcasecmp(hdr->hdr_value, key->hdr_value) == 0) {
			idbuf->hpi_id = dynidx;
			idbuf->hpi_name = hdr->hdr_name;
			idbuf->hpi_value = hdr->hdr_value;
			id = idbuf;
			return (id);
		}
	}

	return (firstid);
}

static int
hpack_table_add(struct hpack_header *hdr, struct hpack_table *hpack)
{
	long		 newsize;

	if (hdr->hdr_index != HPACK_INDEX)
		return (0);

	/*
	 * Following RFC 7451 section 4.1,
	 * the additional 32 octets account for an estimated overhead
	 * associated with an entry.
	 */
	newsize = strlen(hdr->hdr_name) + strlen(hdr->hdr_value) + 32;

	if (newsize > hpack->htb_table_size) {
		/*
		 * An entry larger than the maximum size causes
		 * the table to be emptied of all existing entries.
		 */
		hpack_table_evict(0, newsize, hpack);
		return (0);
	} else
		hpack_table_evict(hpack->htb_table_size,
		    newsize, hpack);

	if (hpack_header_add(hpack->htb_dynamic,
	    hdr->hdr_name, hdr->hdr_value, hdr->hdr_index) == NULL)
		return (-1);
	hpack->htb_dynamic_entries++;
	hpack->htb_dynamic_size += newsize;

	return (0);
}

static int
hpack_table_evict(long size, long newsize, struct hpack_table *hpack)
{
	struct hpack_header	*hdr;

	while (size < (hpack->htb_dynamic_size + newsize) &&
	    (hdr = TAILQ_FIRST(hpack->htb_dynamic)) != NULL) {
		TAILQ_REMOVE(hpack->htb_dynamic, hdr, hdr_entry);
		hpack->htb_dynamic_entries--;
		hpack->htb_dynamic_size -=
		    strlen(hdr->hdr_name) +
		    strlen(hdr->hdr_value) +
		    32;
		hpack_header_free(hdr);
	}

	if (TAILQ_EMPTY(hpack->htb_dynamic) &&
	    hpack->htb_dynamic_entries != 0 &&
	    hpack->htb_dynamic_size != 0)
		errx(1, "corrupted HPACK dynamic table");

	return (0);
}

static int
hpack_table_setsize(long size, struct hpack_table *hpack)
{
	if (size > hpack->htb_max_table_size)
		return (-1);

	if (hpack_table_evict(size, 0, hpack) == -1)
		return (-1);
	hpack->htb_table_size = size;

	return (0);
}

size_t
hpack_table_size(struct hpack_table *hpack)
{
	return ((size_t)hpack->htb_dynamic_size);
}

struct hpack_headerblock *
hpack_decode(unsigned char *data, size_t len, struct hpack_table *hpack)
{
	struct hpack_headerblock	*hdrs = NULL;
	struct hbuf			*hbuf = NULL;
	struct hpack_table		*ctx = NULL;
	int				 ret = -1;

	if (len == 0 || len > LONG_MAX)
		goto fail;

	if (hpack == NULL && (hpack = ctx = hpack_table_new(0)) == NULL)
		goto fail;
	if ((hdrs = hpack_headerblock_new()) == NULL)
		goto fail;

	hpack->htb_headers = hdrs;
	hpack->htb_next = NULL;

	if ((hbuf = hbuf_new(data, len)) == NULL)
		goto fail;

	do {
		if (hpack_decode_buf(hbuf, hpack) == -1)
			goto fail;
	} while (hbuf_left(hbuf) > 0);

	ret = 0;
 fail:
	hbuf_free(hbuf);
	if (ret != 0) {
		hpack_headerblock_free(hdrs);
		hdrs = NULL;
	} else
		hdrs = hpack->htb_headers;
	hpack->htb_headers = NULL;
	hpack->htb_next = NULL;

	/* Free the local table (for single invocations) */
	hpack_table_free(ctx);

	return (hdrs);
}

static long
hpack_decode_int(struct hbuf *buf, unsigned char prefix)
{
	unsigned long	 i = 0;
	unsigned char	 b = 0, m;

	if (hbuf_left(buf) == 0)
		return (-1);

	if (hbuf_readchar(buf, &b) == -1 ||
	    hbuf_advance(buf, 1) == -1)
		return (-1);

	/* Mask and remainder after the prefix of the first octet */
	m = ~prefix;
	i = b & m;

	if (i >= m) {
		m = 0;

		/* Read varint bits while the 0x80 bit is set */
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
    const struct hpack_index **idptr, struct hpack_table *hpack)
{
	struct hpack_index		 idbuf;
	struct hpack_header		*hdr = hpack->htb_next;
	const struct hpack_index	*id;
	long				 i;
	int				 hasvalue;

	if (idptr != NULL)
		*idptr = NULL;

	if ((i = hpack_decode_int(buf, prefix)) == -1)
		return (-1);
	DPRINTF("%s: index %ld", __func__, i);

	if (i == 0)
		return (0);
	if ((id = hpack_table_getbyid(i, &idbuf, hpack)) == NULL) {
		DPRINTF("index not found: %ld\n", i);
		return (-1);
	}

	if (hdr == NULL || hdr->hdr_name != NULL || hdr->hdr_value != NULL)
		errx(1, "invalid header");

	if ((hdr->hdr_name = strdup(id->hpi_name)) == NULL)
		return (-1);
	hasvalue = id->hpi_value == NULL ? 0 : 1;
	if (hasvalue &&
	    (hdr->hdr_value = strdup(id->hpi_value)) == NULL) {
		free(hdr->hdr_name);
		hdr->hdr_name = NULL;
		return (-1);
	}

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
	if ((c & HPACK_M_LITERAL) == HPACK_F_LITERAL_HUFFMAN) {
		DPRINTF("%s: decoding huffman code (size %ld)", __func__, i);
		if ((str = hpack_huffman_decode_str(ptr, (size_t)i)) == NULL)
			return (NULL);
	} else {
		if ((str = calloc(1, (size_t)i + 1)) == NULL)
			return (NULL);
		memcpy(str, ptr, (size_t)i);
	}
	return (str);
}

static int
hpack_decode_literal(struct hbuf *buf, unsigned char prefix,
    struct hpack_table *hpack)
{
	struct hpack_header		*hdr = hpack->htb_next;
	const struct hpack_index	*id;
	long				 i;
	char				*str;

	if ((i = hpack_decode_index(buf, prefix, &id, hpack)) == -1)
		return (-1);

	if (i == 0) {
		if (hdr == NULL ||
		    hdr->hdr_name != NULL || hdr->hdr_value != NULL)
			errx(1, "invalid header");

		if ((str = hpack_decode_str(buf,
		    HPACK_M_LITERAL)) == NULL)
			return (-1);
		DPRINTF("%s: name: %s", __func__, str);
		hdr->hdr_name = str;
	}

	/* The index might have set a default value */
	if (hdr->hdr_value != NULL) {
		free(hdr->hdr_value);
		hdr->hdr_value = NULL;
	}

	if ((str = hpack_decode_str(buf, HPACK_M_LITERAL)) == NULL)
		return (-1);
	DPRINTF("%s: value: %s", __func__, str);
	hdr->hdr_value = str;

	return (0);
}

static int
hpack_decode_buf(struct hbuf *buf, struct hpack_table *hpack)
{
	struct hpack_header	*hdr = NULL;
	unsigned char		 c;
	long			 i;

	if (hbuf_readchar(buf, &c) == -1)
		goto fail;

	if ((hdr = hpack_header_new()) == NULL)
		goto fail;
	hdr->hdr_index = HPACK_NO_INDEX;
	hpack->htb_next = hdr;

	/* 6.1 Indexed Header Field Representation */
	if ((c & HPACK_M_INDEX) == HPACK_F_INDEX) {
		DPRINTF("%s: 0x%02x: 6.1 index", __func__, c);

		/* 7 bit index */
		if ((i = hpack_decode_index(buf,
		    HPACK_M_INDEX, NULL, hpack)) == -1)
			goto fail;

		/* No value means header with empty value */
		if ((hdr->hdr_value == NULL) &&
		    (hdr->hdr_value = strdup("")) == NULL)
			goto fail;
	}

	/* 6.2.1. Literal Header Field with Incremental Indexing */
	else if ((c & HPACK_M_LITERAL_INDEX) == HPACK_F_LITERAL_INDEX) {
		DPRINTF("%s: 0x%02x: 6.2.1 literal indexed", __func__, c);

		/* 6 bit index */
		if (hpack_decode_literal(buf,
		    HPACK_M_LITERAL_INDEX, hpack) == -1)
			goto fail;
		hdr->hdr_index = HPACK_INDEX;
	}

	/* 6.2.2. Literal Header Field without Indexing */
	else if ((c & HPACK_M_LITERAL_NO_INDEX) == HPACK_F_LITERAL_NO_INDEX) {
		DPRINTF("%s: 0x%02x: 6.2.2 literal", __func__, c);

		/* 4 bit index */
		if (hpack_decode_literal(buf,
		    HPACK_M_LITERAL_NO_INDEX, hpack) == -1)
			goto fail;
	}

	/* 6.2.3. Literal Header Field Never Indexed */
	else if ((c & HPACK_M_LITERAL_NO_INDEX) == HPACK_F_LITERAL_NO_INDEX) {
		DPRINTF("%s: 0x%02x: 6.2.3 literal never indexed", __func__, c);

		/* 4 bit index */
		if (hpack_decode_literal(buf,
		    HPACK_M_LITERAL_NO_INDEX, hpack) == -1)
			goto fail;
		hdr->hdr_index = HPACK_NEVER_INDEX;
	}

	/* 6.3. Dynamic Table Size Update */
	else if ((c & HPACK_M_TABLE_SIZE_UPDATE) == HPACK_F_TABLE_SIZE_UPDATE) {
		DPRINTF("%s: 0x%02x: 6.3 dynamic table update", __func__, c);

		/* 5 bit index */
		if ((i = hpack_decode_int(buf,
		    HPACK_M_TABLE_SIZE_UPDATE)) == -1)
			goto fail;

		if (hpack_table_setsize(i, hpack) == -1)
			goto fail;

		return (0);
	}

	/* unknown index */
	else {
		DPRINTF("%s: 0x%02x: unknown index", __func__, c);
		goto fail;
	}

	if (hdr->hdr_name == NULL || hdr->hdr_value == NULL)
		goto fail;

	/* Optionally add to index */
	if (hpack_table_add(hdr, hpack) == -1)
		goto fail;

	/* Add header to the list */
	TAILQ_INSERT_TAIL(hpack->htb_headers, hdr, hdr_entry);
	hpack->htb_next = NULL;

	return (0);
 fail:
	DPRINTF("%s: failed", __func__);
	hpack_header_free(hdr);
	hpack->htb_next = NULL;

	return (-1);
}

unsigned char *
hpack_encode(struct hpack_headerblock *hdrs, size_t *encoded_len,
    struct hpack_table *hpack)
{
	const struct hpack_index	*id;
	struct hpack_index		 idbuf;
	struct hpack_table		*ctx = NULL;
	struct hpack_header		*hdr;
	struct hbuf			*hbuf = NULL;
	unsigned char			 mask, flag;

	if (hpack == NULL && (hpack = ctx = hpack_table_new(0)) == NULL)
		goto fail;

	if ((hbuf = hbuf_new(NULL, BUFSIZ)) == NULL)
		goto fail;

	TAILQ_FOREACH(hdr, hdrs, hdr_entry) {
		DPRINTF("%s: header %s: %s (index %d)", __func__,
		    hdr->hdr_name,
		    hdr->hdr_value == NULL ? "(null)" : hdr->hdr_value,
		    hdr->hdr_index);

		switch (hdr->hdr_index) {
		case HPACK_INDEX:
			mask = HPACK_M_LITERAL_INDEX;
			flag = HPACK_F_LITERAL_INDEX;
			break;
		case HPACK_NO_INDEX:
			mask = HPACK_M_LITERAL_NO_INDEX;
			flag = HPACK_F_LITERAL_NO_INDEX;
			break;
		case HPACK_NEVER_INDEX:
			mask = HPACK_M_LITERAL_NEVER_INDEX;
			flag = HPACK_F_LITERAL_NEVER_INDEX;
			break;
		}

		id = hpack_table_getbyheader(hdr, &idbuf, hpack);

		/* 6.1 Indexed Header Field Representation */
		if (id != NULL && id->hpi_value != NULL) {
			DPRINTF("%s: index %zu (%s: %s)", __func__,
			    id->hpi_id,
			    id->hpi_name,
			    id->hpi_value == NULL ? "(null)" : id->hpi_value);
			if (hpack_encode_int(hbuf, id->hpi_id,
			    HPACK_M_INDEX, HPACK_F_INDEX) == -1)
				goto fail;
			continue;
		}

		/* 6.2 Literal Header Field Representation */
		else if (id != NULL) {
			DPRINTF("%s: index+name %zu, %s", __func__,
			    id->hpi_id,
			    hdr->hdr_value);

			if (hpack_encode_int(hbuf, id->hpi_id,
			    mask, flag) == -1)
				goto fail;
		} else {
			DPRINTF("%s: literal %s: %s", __func__,
			    hdr->hdr_name,
			    hdr->hdr_value);

			if (hpack_encode_int(hbuf, 0, mask, flag) == -1)
				goto fail;

			/* name */
			if (hpack_encode_str(hbuf, hdr->hdr_name) == -1)
				goto fail;
		}

		/* value */
		if (hpack_encode_str(hbuf, hdr->hdr_value) == -1)
			goto fail;

		/* Optionally add to index */
		if (hpack_table_add(hdr, hpack) == -1)
			goto fail;
	}

	return (hbuf_release(hbuf, encoded_len));
 fail:
	hpack_table_free(ctx);
	hbuf_free(hbuf);
	return (NULL);
}

static int
hpack_encode_int(struct hbuf *buf, long i, unsigned char prefix,
    unsigned char type)
{
	unsigned char	b, m;

	if (i < 0)
		return (-1);

	/* The first octet encodes up to prefix length bits */
	m = ~prefix;
	if (i <= m)
		b = (i & m) | type;
	else
		b = m | type;
	if (hbuf_writechar(buf, b) == -1)
		return (-1);
	i -= m;

	/* Encode the remainder as a varint */
	for (m = 0x80; i >= m; i /= m) {
		b = i % m + m;
		/* Set the continuation bit if there are steps left */
		if (i >= m)
			b |= m;
		if (hbuf_writechar(buf, b) == -1)
			return (-1);
	}
	if (i > 0 &&
	    hbuf_writechar(buf, (unsigned char)i) == -1)
		return (-1);

	return (0);
}

static int
hpack_encode_str(struct hbuf *buf, char *str)
{
	unsigned char	*data = NULL;
	size_t		 len, slen;
	int		 ret = -1;

	/*
	 * We have to decide if the string should be encoded with huffman
	 * encoding or as literal string.  There could be better heuristics
	 * to do this...
	 */
	slen = strlen(str);
	if ((data = hpack_huffman_encode(str, slen, &len)) == NULL)
		goto done;
	if (len > 0 && len < slen) {
		DPRINTF("%s: encoded huffman code (size %ld, from %ld)",
		    __func__, len, slen);
		if (hpack_encode_int(buf, len, HPACK_M_LITERAL,
		    HPACK_F_LITERAL_HUFFMAN) == -1)
			goto done;
		if (hbuf_writebuf(buf, data, len) == -1)
			goto done;
	} else {
		if (hpack_encode_int(buf, slen, HPACK_M_LITERAL,
		    HPACK_F_LITERAL) == -1)
			goto done;
		if (hbuf_writebuf(buf, str, slen) == -1)
			goto done;
	}

	ret = 0;
 done:
	free(data);
	return (ret);
}

static int
hpack_huffman_init(void)
{
	struct hpack_huffman		*hph;
	struct hpack_huffman_node	*root, *cur, *node;
	unsigned int			 i, j;

	/* Create new Huffman tree */
	if ((root = hpack_huffman_new()) == NULL)
		return (-1);

	for (i = 0; i < HPACK_HUFFMAN_SIZE; i++) {
		hph = &huffman_table[i];
		cur = root;

		/* Create branch for each symbol */
		for (j = hph->hph_length; j > 0; j--) {
			if ((hph->hph_code >> (j - 1)) & 1) {
				if (cur->hpn_one == NULL) {
					if ((node =
					    hpack_huffman_new()) == NULL)
						goto fail;
					cur->hpn_one = node;
				}
				cur = cur->hpn_one;
			} else {
				if (cur->hpn_zero == NULL) {
					if ((node =
					    hpack_huffman_new()) == NULL)
						goto fail;
					cur->hpn_zero = node;
				}
				cur = cur->hpn_zero;
			}
		}

		/* The leaf node contains the (8-bit ASCII) symbol */
		cur->hpn_sym = i;
	}

	hpack_global.hpack_huffman = root;
	return (0);
 fail:
	hpack_huffman_free(root);
	hpack_global.hpack_huffman = NULL;
	return (-1);
}

unsigned char *
hpack_huffman_decode(unsigned char *buf, size_t len, size_t *decoded_len)
{
	struct hpack_huffman_node	*node, *root;
	unsigned int			 i, j, code;
	struct hbuf			*hbuf = NULL;

	if ((root = node = hpack_global.hpack_huffman) == NULL)
		errx(1, "hpack not initialized");

	if ((hbuf = hbuf_new(NULL, len)) == NULL)
		return (NULL);

	for (i = 0; i < len; i++) {
		code = buf[i];

		/* Walk the Huffman tree for each bit in the encoded input */
		for (j = 8; j > 0; j--) {
			if ((code >> (j - 1)) & 1)
				node = node->hpn_one;
			else
				node = node->hpn_zero;
			if (node->hpn_sym == -1)
				continue;

			/* Leaf node of the next (8-bit ASCII) symbol */
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
hpack_huffman_decode_str(unsigned char *buf, size_t len)
{
	unsigned char	*data;
	char		*str;
	size_t		 data_len;

	if ((data = hpack_huffman_decode(buf, len, &data_len)) == NULL)
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

unsigned char *
hpack_huffman_encode(unsigned char *data, size_t len, size_t *encoded_len)
{
	struct hbuf		*hbuf;
	struct hpack_huffman	*hph;
	unsigned int		 code, i, j;
	unsigned char		 o, obits;

	if ((hbuf = hbuf_new(NULL, len)) == NULL)
		return (NULL);

	for (i = 0, o = 0, obits = 8; i < len; i++) {
		/* Get Huffman code for each (8-bit ASCII) symbol */
		hph = &huffman_table[data[i]];

		for (code = hph->hph_code, j = hph->hph_length; j > 0;) {
			if (j > obits) {
				/* More bits to encode for this symbol */
				j -= obits;
				o |= (code >> j) & 0xff;
				obits = 0;
			} else {
				/*
				 * Remaining bits to encode for this input
				 * symbol.  The current output octet will
				 * include bits from the next symbol or padding.
				 */
				obits -= j;
				o |= (code << obits) & 0xff;
				j = 0;
			}
			if (obits == 0) {
				if (hbuf_writechar(hbuf, o) == -1) {
					DPRINTF("%s: failed to add '%c'",
					    __func__, o);
					goto fail;
				}
				o = 0;
				obits = 8;
			}
		}
	}

	if (len && obits > 0 && obits < 8) {
		/* Pad last octet with ones (EOS) */
		o |= (1 << obits) - 1;
		if (hbuf_writechar(hbuf, o) == -1) {
			DPRINTF("%s: failed to add '%c'", __func__, o);
			goto fail;
		}
	}

	return (hbuf_release(hbuf, encoded_len));
 fail:
	*encoded_len = 0;
	hbuf_free(hbuf);
	return (NULL);
}

static struct hpack_huffman_node *
hpack_huffman_new(void)
{
	struct hpack_huffman_node	*node;

	if ((node = calloc(1, sizeof(*node))) == NULL)
		return (NULL);
	node->hpn_sym = -1;

	return (node);
}

static void
hpack_huffman_free(struct hpack_huffman_node *root)
{
	if (root == NULL)
		return;
	hpack_huffman_free(root->hpn_zero);
	hpack_huffman_free(root->hpn_one);
	free(root);
}

static struct hbuf *
hbuf_new(unsigned char *data, size_t len)
{
	struct hbuf	*buf;
	size_t		 size = len;

	if ((buf = calloc(1, sizeof(*buf))) == NULL)
		return (NULL);
	size = MAX(HPACK_HUFFMAN_BUFSZ, len);
	if ((buf->data = calloc(1, size)) == NULL) {
		free(buf);
		return (NULL);
	}
	if (data != NULL) {
		memcpy(buf->data, data, len);
		buf->wpos = len;
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

	/*
	 * Adjust (shrink) buffer to the used size.  This allows to
	 * safely call recallocarray() or freezero() later.
	 */
	if (buf->wpos != buf->size) {
		if ((data = recallocarray(buf->data,
		    buf->size, buf->wpos, 1)) == NULL) {
			hbuf_free(buf);
			return (NULL);
		}
		buf->data = data;
	}

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
	if (buf->rpos >= buf->wpos)
		return (0);
	return (buf->wpos - buf->rpos);
}

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

#include <ctype.h>

#include "relayd.h"
#include "http2.h"

void	 relay_http2_readpreface(struct bufferevent *, void *);
void	 relay_http2_readframe(struct bufferevent *, void *);
ssize_t	 relay_http2_frame(struct evbuffer *, struct http2_header *,
	    const char **);

static const char *http2_frame_type[] = HTTP2_FRAME_TYPE;
static const char *http2_settings_id[] = HTTP2_SETTINGS_ID;

void
relay_http2(struct rpeer *peer, const char *alpn)
{
	/*
	 * Check if the TLS-ALPN selected the "h2" (HTTP/2) protocol. We only
	 * support the TLS-based HTTP/2 mode and not HTTP/2 over plain TCP.
	 */
	if (strcasecmp("h2", alpn) != 0)
		return;

	/* HTTP/2 is currently only supported on the server side */
	if (peer->dir != RELAY_DIR_REQUEST)
		return;

	log_debug("%s: switching to HTTP/2", __func__);
	peer->bev->readcb = relay_http2_readpreface;
}

void
relay_http2_readpreface(struct bufferevent *bev, void *arg)
{
	struct rpeer		*peer = arg;
	struct rsession		*con = peer->con;
	ssize_t			 prefacelen = sizeof(HTTP2_PREFACE) - 1;
	uint8_t			 preface[prefacelen];
	struct evbuffer		*src = EVBUFFER_INPUT(bev);

	/*
	 * Get and validate the HTTP/2 preface
	 */
	if (evbuffer_remove(src, preface, prefacelen) != prefacelen) {
		relay_close(con, "short HTTP/2 preface", 0);
		return;
	}
	if (memcmp(HTTP2_PREFACE, preface, prefacelen) != 0) {
		relay_close(con, "invalid HTTP/2 preface", 0);
		return;
	}

	bev->readcb = relay_http2_readframe;
	bev->readcb(bev, arg);
}

ssize_t
relay_http2_frame(struct evbuffer *src, struct http2_header *h2,
    const char **errstr)
{
	uint32_t	 length;

	if (evbuffer_remove(src, h2, sizeof(*h2)) != sizeof(*h2)) {
		log_debug("%s: header size %zu", __func__,
		    EVBUFFER_LENGTH(src));
		*errstr = "short HTTP/2 header";
		return (-1);
	}

	/* length is encoded as 24 bits */
	length = h2->h2_length[0] << 16 |
	    h2->h2_length[1] << 8 | h2->h2_length[2];

	if (h2->h2_type >= HTTP2_TYPE_MAX) {
		*errstr = "invalid HTTP/2 frame type";
		return (-1);
	}

	/* XXX check for the reserved bit */
	h2->h2_streamid = ntohl(h2->h2_streamid);

	log_debug("%s: length %u type %s flags 0x%x stream id %u", __func__,
	    length,
	    http2_frame_type[h2->h2_type],
	    h2->h2_flags,
	    h2->h2_streamid);

	return ((ssize_t)length);
}

void
relay_http2_readframe(struct bufferevent *bev, void *arg)
{
	struct hpack_headerblock	*hdrs;
	struct hpack_header		*hdr;
	struct http2_settings		 h2s;
	struct rpeer			*peer = arg;
	struct rsession			*con = peer->con;
	struct http2_header		 h2;
	struct evbuffer			*src = EVBUFFER_INPUT(bev);
	const char			*errstr;
	ssize_t				 length;
	uint8_t				*ptr;
	uint32_t			 window;

	if (EVBUFFER_LENGTH(src) < sizeof(h2))
		return;
	if ((length = relay_http2_frame(src, &h2, &errstr)) == -1) {
		relay_close(con, errstr, 0);
		return;
	}
	if (EVBUFFER_LENGTH(src) < (size_t)length)
		return;

	switch (h2.h2_type) {
	case HTTP2_TYPE_HEADERS:
		ptr = EVBUFFER_DATA(src);
		if (h2.h2_flags & HTTP2_F_HEADERS_PRIORITY) {
			if (length < 6)
				return;
			ptr += 6;
			length -= 6;
		}
		if ((h2.h2_flags & HTTP2_F_HEADERS_END_HEADERS) == 0) {
			relay_close(con, "HTTP/2 non-contigous headers", 0);
		}

		/* XXX */
		if ((hdrs = hpack_decode(ptr, length, NULL)) == NULL) {
			relay_close(con, "HTTP/2 empty HEADERS", 0);
			return;
		}
		TAILQ_FOREACH(hdr, hdrs, hdr_entry) {
			log_debug("%s: header \"%s: %s\"", __func__,
			    hdr->hdr_name, hdr->hdr_value);
		}
		hpack_headerblock_free(hdrs);
		break;

	case HTTP2_TYPE_WINDOW_UPDATE:
		if (EVBUFFER_LENGTH(src) < sizeof(window))
			return;
		if (evbuffer_remove(src, &window,
		    sizeof(window)) != sizeof(window)) {
			relay_close(con, "short HTTP/2 window", 0);
			return;
		}
		window = ntohl(window) & ~0x1;
		log_debug("%s: window update %u", __func__, window);

		h2.h2_length[0] = 0;
		h2.h2_length[1] = 0;
		h2.h2_length[2] = 0;
		if (relay_bufferevent_write(peer, &h2, sizeof(h2)) == -1) {
			relay_close(con, "HTTP/2 window ACK failed", 0);
			return;
		}
		break;

	case HTTP2_TYPE_SETTINGS:
		for (; length >= (ssize_t)sizeof(h2s); length -= sizeof(h2s)) {
			if (EVBUFFER_LENGTH(src) < sizeof(h2s)) {
				log_debug("short");
				return;
			}
			if (evbuffer_remove(src,
			    &h2s, sizeof(h2s)) != sizeof(h2s)) {
				relay_close(con, "short HTTP/2 setting", 0);
				return;
			}
			h2s.h2s_id = ntohs(h2s.h2s_id);
			h2s.h2s_value = ntohl(h2s.h2s_value);

			if (h2s.h2s_id >= SETTINGS_MAX) {
				log_debug("%s: setting <%d>: %d", __func__,
				    h2s.h2s_id,
				    h2s.h2s_value);
			} else {
				log_debug("%s: setting %s: %d", __func__,
				    http2_settings_id[h2s.h2s_id],
				    h2s.h2s_value);
			}
		}

		h2.h2_length[0] = 0;
		h2.h2_length[1] = 0;
		h2.h2_length[2] = 0;
		h2.h2_flags = HTTP2_F_SETTINGS_ACK;
		if (relay_bufferevent_write(peer, &h2, sizeof(h2)) == -1) {
			relay_close(con, "HTTP/2 settings ACK failed", 0);
			return;
		}
		break;

	case HTTP2_TYPE_GOAWAY:
		relay_close(con, "HTTP/2 GOAWAY", 0);
		return;

	default:
		log_debug("%s: unsupported type %d", __func__, h2.h2_type);
		break;
	}

	evbuffer_drain(src, length);
}

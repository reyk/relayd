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

#ifndef HTTP2_H
#define HTTP2_H

#define HTTP2_TLS_ALPN	"h2"
#define HTTP2_TCP_ALPN	"h2c"

#define HTTP2_PREFACE	"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

struct http2_header {
	uint8_t		 h2_length[3];
	uint8_t		 h2_type;
	uint8_t		 h2_flags;
	uint32_t	 h2_streamid;
} __packed;

enum http2_frame_type {
	HTTP2_TYPE_DATA			= 0x0,
	HTTP2_TYPE_HEADERS		= 0x1,
	HTTP2_TYPE_PRIORITY		= 0x2,
	HTTP2_TYPE_RST_STREAM		= 0x3,
	HTTP2_TYPE_SETTINGS		= 0x4,
	HTTP2_TYPE_PUSH_PROMISE		= 0x5,
	HTTP2_TYPE_PING			= 0x6,
	HTTP2_TYPE_GOAWAY		= 0x7,
	HTTP2_TYPE_WINDOW_UPDATE	= 0x8,
	HTTP2_TYPE_CONTINUATION		= 0x9,
};

#define HTTP2_F_SETTINGS_ACK		0x1

struct http2_settings {
	uint16_t	 h2s_id;
	uint32_t	 h2s_value;
} __packed;

enum http2_settings_id {
	SETTINGS_HEADER_TABLE_SIZE	= 0x1,
	SETTINGS_ENABLE_PUSH		= 0x2,
	SETTINGS_MAX_CONCURRENT_STREAMS	= 0x3,
	SETTINGS_INITIAL_WINDOW_SIZE	= 0x4,
	SETTINGS_MAX_FRAME_SIZE		= 0x5,
	SETTINGS_MAX_HEADER_LIST_SIZE	= 0x6,
};

#endif /* HTTP2_H */

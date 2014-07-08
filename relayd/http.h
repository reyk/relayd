/*	$OpenBSD$	*/

/*
 * Copyright (c) 2012 - 2014 Reyk Floeter <reyk@openbsd.org>
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

#ifndef _RELAYD_HTTP_H
#define _RELAYD_HTTP_H

enum httpmethod {
	HTTP_METHOD_NONE	= 0,

	/* HTTP/1.1, RFC 2616 */
	HTTP_METHOD_GET,
	HTTP_METHOD_HEAD,
	HTTP_METHOD_POST,
	HTTP_METHOD_PUT,
	HTTP_METHOD_DELETE,
	HTTP_METHOD_OPTIONS,
	HTTP_METHOD_TRACE,
	HTTP_METHOD_CONNECT,

	/* WebDAV, RFC 4918 */
	HTTP_METHOD_PROPFIND,
	HTTP_METHOD_PROPPATCH,
	HTTP_METHOD_MKCOL,
	HTTP_METHOD_COPY,
	HTTP_METHOD_MOVE,
	HTTP_METHOD_LOCK,
	HTTP_METHOD_UNLOCK,

	/* PATCH, RFC 5789 */
	HTTP_METHOD_PATCH,

	/* Server response (internal value) */
	HTTP_METHOD_RESPONSE
};

struct http_method {
	enum httpmethod		 method_id;
	const char		*method_name;
};
#define HTTP_METHODS		{			\
	{ HTTP_METHOD_GET,		"GET" },	\
	{ HTTP_METHOD_HEAD,		"HEAD" },	\
	{ HTTP_METHOD_POST,		"POST" },	\
	{ HTTP_METHOD_PUT,		"PUT" },	\
	{ HTTP_METHOD_DELETE,		"DELETE" },	\
	{ HTTP_METHOD_OPTIONS,		"OPTIONS" },	\
	{ HTTP_METHOD_TRACE,		"TRACE" },	\
	{ HTTP_METHOD_CONNECT,		"CONNECT" },	\
	{ HTTP_METHOD_PROPFIND,		"PROPFIND" },	\
	{ HTTP_METHOD_PROPPATCH,	"PROPPATCH" },	\
	{ HTTP_METHOD_MKCOL,		"MKCOL" },	\
	{ HTTP_METHOD_COPY,		"COPY" },	\
	{ HTTP_METHOD_MOVE,		"MOVE" },	\
	{ HTTP_METHOD_LOCK,		"LOCK" },	\
	{ HTTP_METHOD_UNLOCK,		"UNLOCK" },	\
	{ HTTP_METHOD_PATCH,		"PATCH" },	\
	{ HTTP_METHOD_NONE,		NULL }		\
}

enum httpheader {
	HTTP_HEADER_NONE	= 0,

	/* HTTP Header Field Registration, RFC 4229 */
	HTTP_HEADER_A_IM,
	HTTP_HEADER_ACCEPT,
	HTTP_HEADER_ACCEPT_ADDITIONS,
	HTTP_HEADER_ACCEPT_CHARSET,
	HTTP_HEADER_ACCEPT_ENCODING,
	HTTP_HEADER_ACCEPT_FEATURES,
	HTTP_HEADER_ACCEPT_LANGUAGE,
	HTTP_HEADER_ACCEPT_RANGES,
	HTTP_HEADER_AGE,
	HTTP_HEADER_ALLOW,
	HTTP_HEADER_ALTERNATES,
	HTTP_HEADER_AUTHENTICATION_INFO,
	HTTP_HEADER_AUTHORIZATION,
	HTTP_HEADER_C_EXT,
	HTTP_HEADER_C_MAN,
	HTTP_HEADER_C_OPT,
	HTTP_HEADER_C_PEP,
	HTTP_HEADER_C_PEP_INFO,
	HTTP_HEADER_CACHE_CONTROL,
	HTTP_HEADER_CONNECTION,
	HTTP_HEADER_CONTENT_BASE,
	HTTP_HEADER_CONTENT_DISPOSITION,
	HTTP_HEADER_CONTENT_ENCODING,
	HTTP_HEADER_CONTENT_ID,
	HTTP_HEADER_CONTENT_LANGUAGE,
	HTTP_HEADER_CONTENT_LENGTH,
	HTTP_HEADER_CONTENT_LOCATION,
	HTTP_HEADER_CONTENT_MD5,
	HTTP_HEADER_CONTENT_RANGE,
	HTTP_HEADER_CONTENT_SCRIPT_TYPE,
	HTTP_HEADER_CONTENT_STYLE_TYPE,
	HTTP_HEADER_CONTENT_TYPE,
	HTTP_HEADER_CONTENT_VERSION,
	HTTP_HEADER_COOKIE,
	HTTP_HEADER_COOKIE2,
	HTTP_HEADER_DAV,
	HTTP_HEADER_DATE,
	HTTP_HEADER_DEFAULT_STYLE,
	HTTP_HEADER_DELTA_BASE,
	HTTP_HEADER_DEPTH,
	HTTP_HEADER_DERIVED_FROM,
	HTTP_HEADER_DESTINATION,
	HTTP_HEADER_DIFFERENTIAL_ID,
	HTTP_HEADER_DIGEST,
	HTTP_HEADER_ETAG,
	HTTP_HEADER_EXPECT,
	HTTP_HEADER_EXPIRES,
	HTTP_HEADER_EXT,
	HTTP_HEADER_FROM,
	HTTP_HEADER_GETPROFILE,
	HTTP_HEADER_HOST,
	HTTP_HEADER_IM,
	HTTP_HEADER_IF,
	HTTP_HEADER_IF_MATCH,
	HTTP_HEADER_IF_MODIFIED_SINCE,
	HTTP_HEADER_IF_NONE_MATCH,
	HTTP_HEADER_IF_RANGE,
	HTTP_HEADER_IF_UNMODIFIED_SINCE,
	HTTP_HEADER_KEEP_ALIVE,
	HTTP_HEADER_LABEL,
	HTTP_HEADER_LAST_MODIFIED,
	HTTP_HEADER_LINK,
	HTTP_HEADER_LOCATION,
	HTTP_HEADER_LOCK_TOKEN,
	HTTP_HEADER_MIME_VERSION,
	HTTP_HEADER_MAN,
	HTTP_HEADER_MAX_FORWARDS,
	HTTP_HEADER_METER,
	HTTP_HEADER_NEGOTIATE,
	HTTP_HEADER_OPT,
	HTTP_HEADER_ORDERING_TYPE,
	HTTP_HEADER_OVERWRITE,
	HTTP_HEADER_P3P,
	HTTP_HEADER_PEP,
	HTTP_HEADER_PICS_LABEL,
	HTTP_HEADER_PEP_INFO,
	HTTP_HEADER_POSITION,
	HTTP_HEADER_PRAGMA,
	HTTP_HEADER_PROFILEOBJECT,
	HTTP_HEADER_PROTOCOL,
	HTTP_HEADER_PROTOCOL_INFO,
	HTTP_HEADER_PROTOCOL_QUERY,
	HTTP_HEADER_PROTOCOL_REQUEST,
	HTTP_HEADER_PROXY_AUTHENTICATE,
	HTTP_HEADER_PROXY_AUTHENTICATION_INFO,
	HTTP_HEADER_PROXY_AUTHORIZATION,
	HTTP_HEADER_PROXY_FEATURES,
	HTTP_HEADER_PROXY_INSTRUCTION,
	HTTP_HEADER_PUBLIC,
	HTTP_HEADER_RANGE,
	HTTP_HEADER_REFERER,
	HTTP_HEADER_RETRY_AFTER,
	HTTP_HEADER_SAFE,
	HTTP_HEADER_SECURITY_SCHEME,
	HTTP_HEADER_SERVER,
	HTTP_HEADER_SET_COOKIE,
	HTTP_HEADER_SET_COOKIE2,
	HTTP_HEADER_SETPROFILE,
	HTTP_HEADER_SOAPACTION,
	HTTP_HEADER_STATUS_URI,
	HTTP_HEADER_SURROGATE_CAPABILITY,
	HTTP_HEADER_SURROGATE_CONTROL,
	HTTP_HEADER_TCN,
	HTTP_HEADER_TE,
	HTTP_HEADER_TIMEOUT,
	HTTP_HEADER_TRAILER,
	HTTP_HEADER_TRANSFER_ENCODING,
	HTTP_HEADER_URI,
	HTTP_HEADER_UPGRADE,
	HTTP_HEADER_USER_AGENT,
	HTTP_HEADER_VARIANT_VARY,
	HTTP_HEADER_VARY,
	HTTP_HEADER_VIA,
	HTTP_HEADER_WWW_AUTHENTICATE,
	HTTP_HEADER_WANT_DIGEST,
	HTTP_HEADER_WARNING,

	/* PATCH, RFC 5789 */
	HTTP_HEADER_ACCEPT_PATCH,

	/* Other extensions */
	HTTP_HEADER_X_REQUESTED_WITH,	/* AJAX */
	HTTP_HEADER_X_FORWARDED_FOR,
	HTTP_HEADER_X_FORWARDED_BY,
	HTTP_HEADER_X_POWERED_BY,
	HTTP_HEADER_X_XSS_PROTECTION,
	HTTP_HEADER_ORIGIN,		/* Anti-XSRF */
	HTTP_HEADER_DNT,		/* Do-Not-Track */

	/* Array size */
	HTTP_HEADER_MAX,
#define	HTTP_HEADER_OTHER		HTTP_HEADER_MAX
};

struct http_header {
	enum httpheader		 header_id;
	const char		*header_name;
	int			 header_isused;
};
/* Has to be sorted alphabetically */
#define HTTP_HEADERS		{					\
	{ HTTP_HEADER_ACCEPT,			"Accept" },		\
	{ HTTP_HEADER_ACCEPT_ADDITIONS,		"Accept-Additions" },	\
	{ HTTP_HEADER_ACCEPT_CHARSET,		"Accept-Charset" },	\
	{ HTTP_HEADER_ACCEPT_ENCODING,		"Accept-Encoding" },	\
	{ HTTP_HEADER_ACCEPT_FEATURES,		"Accept-Features" },	\
	{ HTTP_HEADER_ACCEPT_LANGUAGE,		"Accept-Language" },	\
	{ HTTP_HEADER_ACCEPT_PATCH,		"Accept-Patch" },	\
	{ HTTP_HEADER_ACCEPT_RANGES,		"Accept-Ranges" },	\
	{ HTTP_HEADER_AGE,			"Age" },		\
	{ HTTP_HEADER_ALLOW,			"Allow" },		\
	{ HTTP_HEADER_ALTERNATES,		"Alternates" },		\
	{ HTTP_HEADER_AUTHENTICATION_INFO,	"Authentication-Info" },\
	{ HTTP_HEADER_AUTHORIZATION,		"Authorization" },	\
	{ HTTP_HEADER_A_IM,			"A-IM" },		\
	{ HTTP_HEADER_CACHE_CONTROL,		"Cache-Control" },	\
	{ HTTP_HEADER_CONNECTION,		"Connection" },		\
	{ HTTP_HEADER_CONTENT_BASE,		"Content-Base" },	\
	{ HTTP_HEADER_CONTENT_DISPOSITION,	"Content-Disposition" },\
	{ HTTP_HEADER_CONTENT_ENCODING,		"Content-Encoding" },	\
	{ HTTP_HEADER_CONTENT_ID,		"Content-ID" },		\
	{ HTTP_HEADER_CONTENT_LANGUAGE,		"Content-Language" },	\
	{ HTTP_HEADER_CONTENT_LENGTH,		"Content-Length" },	\
	{ HTTP_HEADER_CONTENT_LOCATION,		"Content-Location" },	\
	{ HTTP_HEADER_CONTENT_MD5,		"Content-MD5" },	\
	{ HTTP_HEADER_CONTENT_RANGE,		"Content-Range" },	\
	{ HTTP_HEADER_CONTENT_SCRIPT_TYPE,	"Content-Script-Type" },\
	{ HTTP_HEADER_CONTENT_STYLE_TYPE,	"Content-Style-Type" },	\
	{ HTTP_HEADER_CONTENT_TYPE,		"Content-Type" },	\
	{ HTTP_HEADER_CONTENT_VERSION,		"Content-Version" },	\
	{ HTTP_HEADER_COOKIE,			"Cookie" },		\
	{ HTTP_HEADER_COOKIE2,			"Cookie2" },		\
	{ HTTP_HEADER_C_EXT,			"C-Ext" },		\
	{ HTTP_HEADER_C_MAN,			"C-Man" },		\
	{ HTTP_HEADER_C_OPT,			"C-Opt" },		\
	{ HTTP_HEADER_C_PEP,			"C-PEP" },		\
	{ HTTP_HEADER_C_PEP_INFO,		"C-PEP-Info" },		\
	{ HTTP_HEADER_DATE,			"Date" },		\
	{ HTTP_HEADER_DAV,			"DAV" },		\
	{ HTTP_HEADER_DEFAULT_STYLE,		"Default-Style" },	\
	{ HTTP_HEADER_DELTA_BASE,		"Delta-Base" },		\
	{ HTTP_HEADER_DEPTH,			"Depth" },		\
	{ HTTP_HEADER_DERIVED_FROM,		"Derived-From" },	\
	{ HTTP_HEADER_DESTINATION,		"Destination" },	\
	{ HTTP_HEADER_DIFFERENTIAL_ID,		"Differential-Id" },	\
	{ HTTP_HEADER_DIGEST,			"Digest" },		\
	{ HTTP_HEADER_DNT,			"DNT" },		\
	{ HTTP_HEADER_ETAG,			"ETag" },		\
	{ HTTP_HEADER_EXPECT,			"Expect" },		\
	{ HTTP_HEADER_EXPIRES,			"Expires" },		\
	{ HTTP_HEADER_EXT,			"Ext" },		\
	{ HTTP_HEADER_FROM,			"From" },		\
	{ HTTP_HEADER_GETPROFILE,		"GetProfile" },		\
	{ HTTP_HEADER_HOST,			"Host", 1 /* used */ },	\
	{ HTTP_HEADER_IF,			"If" },			\
	{ HTTP_HEADER_IF_MATCH,			"If-Match" },		\
	{ HTTP_HEADER_IF_MODIFIED_SINCE,	"If-Modified-Since" },	\
	{ HTTP_HEADER_IF_NONE_MATCH,		"If-None-Match" },	\
	{ HTTP_HEADER_IF_RANGE,			"If-Range" },		\
	{ HTTP_HEADER_IF_UNMODIFIED_SINCE,	"If-Unmodified-Since" },\
	{ HTTP_HEADER_IM,			"IM" },			\
	{ HTTP_HEADER_KEEP_ALIVE,		"Keep-Alive" },		\
	{ HTTP_HEADER_LABEL,			"Label" },		\
	{ HTTP_HEADER_LAST_MODIFIED,		"Last-Modified" },	\
	{ HTTP_HEADER_LINK,			"Link" },		\
	{ HTTP_HEADER_LOCATION,			"Location" },		\
	{ HTTP_HEADER_LOCK_TOKEN,		"Lock-Token" },		\
	{ HTTP_HEADER_MAN,			"Man" },		\
	{ HTTP_HEADER_MAX_FORWARDS,		"Max-Forwards" },	\
	{ HTTP_HEADER_METER,			"Meter" },		\
	{ HTTP_HEADER_MIME_VERSION,		"MIME-Version" },	\
	{ HTTP_HEADER_NEGOTIATE,		"Negotiate" },		\
	{ HTTP_HEADER_OPT,			"Opt" },		\
	{ HTTP_HEADER_ORDERING_TYPE,		"Ordering-Type" },	\
	{ HTTP_HEADER_ORIGIN,			"Origin" },		\
	{ HTTP_HEADER_OVERWRITE,		"Overwrite" },		\
	{ HTTP_HEADER_P3P,			"P3P" },		\
	{ HTTP_HEADER_PEP,			"PEP" },		\
	{ HTTP_HEADER_PEP_INFO,			"Pep-Info" },		\
	{ HTTP_HEADER_PICS_LABEL,		"PICS-Label" },		\
	{ HTTP_HEADER_POSITION,			"Position" },		\
	{ HTTP_HEADER_PRAGMA,			"Pragma" },		\
	{ HTTP_HEADER_PROFILEOBJECT,		"ProfileObject" },	\
	{ HTTP_HEADER_PROTOCOL,			"Protocol" },		\
	{ HTTP_HEADER_PROTOCOL_INFO,		"Protocol-Info" },	\
	{ HTTP_HEADER_PROTOCOL_QUERY,		"Protocol-Query" },	\
	{ HTTP_HEADER_PROTOCOL_REQUEST,		"Protocol-Request" },	\
	{ HTTP_HEADER_PROXY_AUTHENTICATE,	"Proxy-Authenticate" },	\
	{ HTTP_HEADER_PROXY_AUTHENTICATION_INFO,"Proxy-Authenticate-Info" },\
	{ HTTP_HEADER_PROXY_AUTHORIZATION,	"Proxy-Authorization" },\
	{ HTTP_HEADER_PROXY_FEATURES,		"Proxy-Features" },	\
	{ HTTP_HEADER_PROXY_INSTRUCTION,	"Proxy-Instruction" },	\
	{ HTTP_HEADER_PUBLIC,			"Public" },		\
	{ HTTP_HEADER_RANGE,			"Range" },		\
	{ HTTP_HEADER_REFERER,			"Referer" },		\
	{ HTTP_HEADER_RETRY_AFTER,		"Retry-After" },	\
	{ HTTP_HEADER_SAFE,			"Safe" },		\
	{ HTTP_HEADER_SECURITY_SCHEME,		"Security-Scheme" },	\
	{ HTTP_HEADER_SERVER,			"Server" },		\
	{ HTTP_HEADER_SETPROFILE,		"SetProfile" },		\
	{ HTTP_HEADER_SET_COOKIE,		"Set-Cookie" },		\
	{ HTTP_HEADER_SET_COOKIE2,		"Set-Cookie2" },	\
	{ HTTP_HEADER_SOAPACTION,		"SoapAction" },		\
	{ HTTP_HEADER_STATUS_URI,		"Status-URI" },		\
	{ HTTP_HEADER_SURROGATE_CAPABILITY,	"Surrogate-Capability" },\
	{ HTTP_HEADER_SURROGATE_CONTROL,	"Surrogate-Control" },	\
	{ HTTP_HEADER_TCN,			"TCN" },		\
	{ HTTP_HEADER_TE,			"TE" },			\
	{ HTTP_HEADER_TIMEOUT,			"Timeout" },		\
	{ HTTP_HEADER_TRAILER,			"Trailer" },		\
	{ HTTP_HEADER_TRANSFER_ENCODING,	"Transfer-Encoding" },	\
	{ HTTP_HEADER_UPGRADE,			"Upgrade" },		\
	{ HTTP_HEADER_URI,			"URI" },		\
	{ HTTP_HEADER_USER_AGENT,		"User-Agent" },		\
	{ HTTP_HEADER_VARIANT_VARY,		"Variant-Vary" },	\
	{ HTTP_HEADER_VARY,			"Vary" },		\
	{ HTTP_HEADER_VIA,			"Via" },		\
	{ HTTP_HEADER_WANT_DIGEST,		"Want-Digest" },	\
	{ HTTP_HEADER_WARNING,			"Warning" },		\
	{ HTTP_HEADER_WWW_AUTHENTICATE,		"WWW-Authenticate" },	\
	{ HTTP_HEADER_X_FORWARDED_BY,		"X-Forwarded-By" },	\
	{ HTTP_HEADER_X_FORWARDED_FOR,		"X-Forwarded-For" },	\
	{ HTTP_HEADER_X_POWERED_BY,		"X-Powered-By" },	\
	{ HTTP_HEADER_X_REQUESTED_WITH,		"X-Requested-With" },	\
	{ HTTP_HEADER_X_XSS_PROTECTION,		"X-XSS-Protection" },	\
	{ HTTP_HEADER_OTHER,			NULL }			\
}

/* Used during runtime */
struct http_descriptor {
	struct kv		 http_pathquery;
	struct kv		 http_matchquery;
#define http_path		 http_pathquery.kv_key
#define http_query		 http_pathquery.kv_value
#define http_rescode		 http_pathquery.kv_key
#define http_resmesg		 http_pathquery.kv_value
#define query_key		 http_matchquery.kv_key
#define query_val		 http_matchquery.kv_value

	char			*http_version;
	enum httpmethod		 http_method;
	int			 http_chunked;

	/*
	 * A linked list of headers and an array with pointers
	 * pointing to well-known headers that have been found to
	 * speed up lookups.
	 */
	struct kvlist		 http_headers;
	struct kv		*http_header[HTTP_HEADER_MAX];
};

#endif /* _RELAYD_HTTP_H */

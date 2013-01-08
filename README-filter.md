relayd filter rewrite
=====================

This branch includes an experimental and unfinished rewrite of the
relay filter implementation.  The rewrite includes a new filter
configuration grammar and a new engine replacing the "protocol nodes"
code.  The code aims to provide a better flexibility, grammar and
gammar of the filters.

Please see some design notes below, more details can be found in the
code of the relayd/ directory for now.

FILTERS HOOKS
=============

OLD:
----

1. per-line header filter
	1. gather information
		* path			-> HOOK
		* url			-> HOOK
		* http header		-> HOOK
	2. modify/delete headers
	3. action

2. after headers: resolve information
	1. append/check headers		-> HOOK
	2. action

pros: efficiency (inline modifications),
cons: complexity

NEW:
----

1. gather information
	1. scan input header
	2. create meta header (see pf descriptors)
2. resolve information
	1. scan/modify meta header	-> HOOK
	2. action
	3. create output header

pros: simplicity, flexibility, better code,
cons: memory usage (extra meta header)

GRAMMAR
=======

OLD: HTTP-centric view
----------------------


```
+--------+ request                 relayd                            +--------+
|        |---------------------------------------------------------->|        |
| client | response                                                  | server |
|        |<----------------------------------------------------------|        |
+--------+                                                           +--------+
```

	header append "$REMOTE_ADDR" to "X-Forwarded-For"
	header append "$SERVER_ADDR:$SERVER_PORT" to "X-Forwarded-By"
	header change "Connection" to "close"

	# Block disallowed sites
	label "URL filtered!"
	request url filter "www.example.com/"

	# Block disallowed browsers
	label "Please try a <em>different Browser</em>"
	header filter "Mozilla/4.0 (compatible; MSIE *" from "User-Agent"

	# Block some well-known Instant Messengers
	label "Instant messenger disallowed!"
	response header filter "application/x-msn-messenger" from "Content-Type"
	response header filter "app/x-hotbar-xip20" from "Content-Type"
	response header filter "application/x-icq" from "Content-Type"
	response header filter "AIM/HTTP" from "Content-Type"
	response header filter "application/x-comet-log" from "Content-Type"

NEW: pf-style filter engine and language
----------------------------------------


```
+--------+          (request) in +--------+ out                      +--------+
|        |---------------------->|        |------------------------->|        |
| client |                   out | relayd | in (response)            | server |
|        |<----------------------|        |<-------------------------|        |
+--------+                       +--------+                          +--------+
```

**This grammar is not fixed yet, the examples below are just initial tests.**

	# XXX better append/change grammar?!
	match request header append "X-Forwarded-For" value "$REMOTE_ADDR"
	match request header append "X-Forwarded-By" value "$REMOTE_ADDR:$SERVER_PORT"
	match request header set "Connect" value "close"

	# XXX directions? request/response not really bidirectional!
	# XXX "interfaces" client/server "pass in on server"? better grammar?
	block client in url "www.example.com/" tag "URL filtered!"
	pass client in from 10.0.0.1 url "www.example.com/"

	# XXX sticky labels with last match? (see pf tags)
	match request header "User-Agent" tag "Please try a <em>different Browser</em>"
	block request header "User-Agent" value "Mozilla/4.0 (compatible; MSIE *"

	# XXX lists
	match response tag "Instant messenger disallowed!"
	block response header "Content-Type" value {
		"application/x-msn-messenger"
		"app/x-hotbar-xip20"
		"application/x-icq"
		"AIM/HTTP"
		"application/x-comet-log"
	}

	# change relay destination based on filter (improved framework)
	match request path "/images" relay-to 10.1.1.1
	match request path "/videos" relay-to <otherhosts>

	# dns-specific
	block response host www.openbsd.org value 192.168.1.1
	block response host any value 192.168.1.1
	block response header "flags0" value 0x00/0x00

SYNTAX
------

```
[pass|block|match]
	[request|response|[client|server] [in|out]]
	[inet|inet6]
	[proto tcp|udp]
	[from any|address|mask]
	[to any|address|mask]
	[[append|change|expect]
		header|host|url|path|cookie|query
		[value number|mask|string]
	]
	[tag string]
	[tagged string]
	[label string]
	[relay-to host]
```

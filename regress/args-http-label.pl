use strict;
use warnings;

our %args = (
    client => {
	func => \&http_client,
	loggrep => qr/403 Forbidden/,
	path => "query?foo=bar&ok=yes",
	httpnok => 1,
    },
    relayd => {
	protocol => [ "http",
	    'return error',
	    'block',
	    'match request query log "foo" value "bar" label "expect_foobar_label"',
	],
	loggrep => qr/Forbidden.*403 Forbidden.*expect_foobar_label.*foo: bar/,
    },
    server => {
	func => \&http_server,
	nocheck => 1,
    },
);

1;

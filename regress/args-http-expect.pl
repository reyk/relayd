use strict;
use warnings;

my @lengths = (21);
our %args = (
    client => {
	func => \&http_client,
	lengths => \@lengths,
	path => "query?foo=bar&ok=yes"
    },
    relayd => {
	protocol => [ "http",
	    'block request',
	    'pass request query log "foo" value "bar" ',
	    'pass request query log "ok" value "maybe" ',
	],
	loggrep => { qr/\[foo: bar\]/ => 1 }
    },
    server => {
	func => \&http_server,
    },
    lengths => \@lengths,
);

1;

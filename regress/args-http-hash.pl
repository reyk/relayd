use strict;
use warnings;

our %args = (
    client => {
	func => \&http_client,
	path => "query?foobar",
	len => 21,
	nocheck => 1,
    },
    relayd => {
	table => 1,
	protocol => [ "http",
	    'match request path hash "/query"',
	],
	relay => 'forward to <table-$test> port $connectport',
	loggrep => { qr/relay_action: hashkey 0x7dc0306a/ => 1 },
    },
    server => {
	func => \&http_server,
	nocheck => 1,
    },
);

1;

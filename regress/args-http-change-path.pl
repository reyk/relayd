use strict;
use warnings;

our %args = (
    client => {
	func => \&http_client,
	loggrep => { 
		qr/GET \/251 HTTP\/1\.0/ => 1,
	},
    },
    relayd => {
	protocol => [ "http",
	    'match request path set "*" value "/foopath"',
	],
	loggrep => { qr/\, done/ => 1 },
    },
    server => {
	func => \&http_server,
	loggrep => { 
		qr/GET \/foopath HTTP\/1\.0/ => 1,
	},
    },
);

1;

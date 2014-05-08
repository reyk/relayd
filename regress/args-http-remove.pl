use strict;
use warnings;

my %header = (
	"X-Header-Foo" => "foo",
	"X-Header-Bar" => "bar",
);
our %args = (
    client => {
	func => \&http_client,
	nocheck => 1,
	loggrep => {
	    "X-Header-Foo: foo" => 0,
	    "X-Header-Bar: bar" => 1,
	},
    },
    relayd => {
	protocol => [ "http",
	    'match response header remove X-Header-Foo',
	],
	loggrep => { qr/done/ => 1 },
    },
    server => {
	func => \&http_server,
	header => \%header,
	loggrep => {
	    "X-Header-Foo: foo" => 1,
	    "X-Header-Bar: bar" => 1,
	},
    },
);

1;

# test http connection over http relay

use strict;
use warnings;

our %args = (
    client => {
	func => \&http_client,
    },
    relayd => {
	protocol => [ "http",
	    "match request header log foo",
	    "match response header log bar",
	],
    },
    server => {
	func => \&http_server,
    },
    len => 251,
    md5 => "bc3a3f39af35fe5b1687903da2b00c7f",
);

1;

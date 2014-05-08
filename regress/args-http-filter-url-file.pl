use strict;
use warnings;

my @lengths = (1, 2, 4, 0, 3);
our %args = (
    client => {
	func => sub { eval { http_client(@_) }; warn $@ },
	lengths => \@lengths,
	loggrep => {
		qr/Forbidden/ => 1,
		qr/Content-Length\: 3/ => 0,
		qr/Content-Length\: 4/ => 1,
	},
    },
    relayd => {
	protocol => [ "http",
	    'return error',
	    'pass',
	    'block request url log file args-http-filter-url-file.in label "test_reject_label"',
	],
	loggrep => {
		qr/Forbidden/ => 1,
		qr/\[test_reject_label\, foo\.bar\/0\]/ => 1
	},
    },
    server => {
	func => \&http_server,
	lengths => (1, 2, 4),
    },
);

1;

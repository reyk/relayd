use strict;
use warnings;

our %args = (
    client => {
	func => \&http_client,
	len => 1,
	loggrep => { "X-Server-Append: 127.0.0.1:.*" => 1 },
    },
    relayd => {
	protocol => [ "http",
	    'match header append X-Client-Append value "$REMOTE_ADDR:$REMOTE_PORT"',
	    'match response header append X-Server-Append value "$SERVER_ADDR:$SERVER_PORT"',
	],
    },
    server => {
	func => \&http_server,
	loggrep => { "X-Client-Append: 127.0.0.1:.*" => 1 },
    },
);

1;

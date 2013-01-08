relayd
======

OpenBSD relayd daemon -experimental

relayd is a daemon to relay and dynamically redirect incoming
connections to a target host.  Its main purposes are to run as a
load-balancer, application layer gateway, or transparent proxy.  The
daemon is able to monitor groups of hosts for availability, which is
determined by checking for a specific service common to a host group.
When availability is confirmed, layer 3 and/or layer 7 forwarding
services are set up by relayd.

This repository includes an occasionally updated copy of the original
relayd source tree plus experimental branches that need to be shared
with other people.  This is not a portable version and is only
intended for OpenBSD!  This repository might include highly
experimental changes, please do not use it in production.  The main
development is happening in OpenBSD's CVS tree, please refer to it for
any authoritative use:

* http://www.openbsd.org/cgi-bin/cvsweb/src/usr.sbin/relayd/
* http://www.openbsd.org/cgi-bin/cvsweb/src/usr.sbin/relayctl/
* http://www.openbsd.org/cgi-bin/cvsweb/src/usr.sbin/snmpd/snmp.h
* http://www.openbsd.org/cgi-bin/cvsweb/src/regress/usr.sbin/relayd/

License
=======

relayd is free software under OpenBSD's ISC-style license.

* Most of the code has been written by Reyk Floeter <reyk@openbsd.org>
* The regress tests have been written by Alexander Bluhm <bluhm@openbsd.org>
* Please refer to the individual source files for other copyright holders!

Copyright (c) 2010-2013 Reyk Floeter <reyk@openbsd.org>

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

[![Flattr this git repo](http://api.flattr.com/button/flattr-badge-large.png)](https://flattr.com/thing/1094377/OpenBSD-relayd)

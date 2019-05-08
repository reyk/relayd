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

* http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.sbin/relayd/
* http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.sbin/relayctl/
* http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.sbin/snmpd/snmp.h
* http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/regress/usr.sbin/relayd/

The official relayd page can be found at [bsd.plumbing](http://bsd.plumbing/).

See [`LICENSE.md`](https://github.com/reyk/relayd/blob/master/LICENSE.md)
for information about copyright and licensing.

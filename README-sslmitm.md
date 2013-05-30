relayd SSL Inspection ("SSL-MITM")
==================================

This branch includes experimental support for SSL inspection, an SSL
Man-In-The-Middle attack.  relayd will intercept SSL connections and
update the server SSL certificates on the fly by using a local RSA key
signing them with a local CA.  The clients will accept the forged
server certificate if they trust the local CA.  This is typically done
by either installing the local CA cert in the clients CA chain (eg.
the accepted CA certificates of the browser), or by using a CA
certificate that was signed by a root CA that is already accepted by
the client.  The latter is typically only possible for governmental
authorities. 

Configuration
-------------

* /etc/pf.conf
```
# Divert incoming HTTPS traffic to relayd
pass in on vlan1 inet proto tcp to port 443 divert-to localhost port 8443
```

* /etc/relayd.conf
```
http protocol httpfilter {
        # Return HTTP/HTML error pages to the client
        return error

        # Block disallowed sites
        label "URL filtered!"
        request url filter "www.example.com/"

        # Block disallowed browsers
        label "Please try a <em>different Browser</em>"
        header filter "Mozilla/4.0 (compatible; MSIE *" from "User-Agent"

        # Block some well-known Instant Messengers
        label "Instant messenger disallowed!"
        response header filter "application/x-msn-messenger" from "Content-Type"
        response header filter "app/x-hotbar-xip20" from "Content-Type"
        response header filter "application/x-icq" from "Content-Type"
        response header filter "AIM/HTTP" from "Content-Type"
        response header filter "application/x-comet-log" from "Content-Type"

        ssl ca key "/etc/ssl/private/ca.key" password "humppa"
        ssl ca cert "/etc/ssl/ca.crt"
}
```
```
relay sslproxy {
        # Listen on localhost, accept diverted connections from pf(4)
        listen on 127.0.0.1 port 8443 ssl
        protocol httpfilter

        # Forward to the original target host
        forward with ssl to destination
}
```

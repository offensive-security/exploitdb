#!/usr/bin/env python

# Typewriter Shellcode Generator
# Paw Petersen, SLAE-656
# https://www.pawpetersen.dk/typewriter-shellcode-generator-linux-x86/

import sys,struct

string = sys.argv[1]

length = struct.pack("<b",len(string)+1)

asm_string_chunk = ""
for chunk_start in range(0,len(string),4):
	chunk = string[chunk_start:chunk_start+4]
	if chunk_start+4 >= len(string):
		if len(chunk) < 4:
			asm_string_chunk = ("\x68"+struct.pack("<4s",chunk+"\x0a"*(4-len(chunk))))+asm_string_chunk
		else:
			asm_string_chunk = ("\x68"+struct.pack("<4s",chunk))+asm_string_chunk
			asm_string_chunk = ("\x68"+struct.pack("<4s","\x0a"*4))+asm_string_chunk
	else:
		asm_string_chunk = ("\x68"+struct.pack("<4s",chunk))+asm_string_chunk

sc = asm_string_chunk+"\x31\xc9\xb1"+length+"\x51\xb8\x11\x11\x51\x08\x50\x31\xc0\x50\x54\x51\x89\xe6\x83\xc6\x14\x03\x74\x24\x10\x2b\x34\x24\x56\x89\xf1\xeb\x1c\xeb\x0c\x59\x59\xe2\xe8\x31\xdb\x31\xc0\xb0\x01\xcd\x80\x31\xc0\xb0\xa2\x8d\x5c\x24\x0c\x31\xc9\xcd\x80\xeb\xe6\x31\xd2\xb2\x01\x31\xdb\xb3\x01\x31\xc0\xb0\x04\xcd\x80\xeb\xd4"

print '"' + ''.join('\\x%02x' % ord(c) for c in sc) + '";'
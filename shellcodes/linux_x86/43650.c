#include <stdio.h>

const char shellcode[]=
	"\x40"			// inc	%eax
//	"\x43"			// inc	%ebx
	"\xcd\x80";		// int	$0x80

int main()
{
	printf	("\n[+] Yet conditional (%eax==0) Linux/x86 exit(0) 3 bytes or
exit(1) 4 bytes"
		"\n[+] Date: 18/06/2009"
		"\n[+] Author: TheWorm"
		"\n\n[+] Shellcode Size: %d bytes\n\n", sizeof(shellcode)-1);
	(*(void (*)()) shellcode)();
	return 0;
}
